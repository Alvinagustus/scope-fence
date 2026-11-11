"""Store layer for scope-fence: plugin_db schema + in-memory cache + audit."""
import logging
import os
import sqlite3
import time
import threading

log = logging.getLogger(__name__)

_DB_LOCAL = threading.local()
_CACHE = {}
_CACHE_LOCK = threading.Lock()


def _get_db(hermes_home: str = None):
    """Get a thread-local database connection via the official plugin_db() API."""
    conn = getattr(_DB_LOCAL, "conn", None)
    if conn is not None:
        return conn
    try:
        from plugins.plugin_storage import plugin_db
        conn = plugin_db("scope-fence")
    except Exception as e:
        log.warning("scope-fence: plugin_db unavailable (%s); using fallback", e)
        # Fallback for isolated test environments without the Hermes plugin host
        if hermes_home is None:
            try:
                from hermes_constants import get_hermes_home
                hermes_home = str(get_hermes_home())
            except ImportError:
                hermes_home = os.path.expanduser("~/.hermes")
        data_dir = os.path.join(hermes_home, "plugin-data", "scope-fence")
        os.makedirs(data_dir, exist_ok=True)
        db_path = os.path.join(data_dir, "data.db")
        conn = sqlite3.connect(db_path, check_same_thread=False)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
    try:
        _ensure_schema(conn)
    except Exception as e:
        log.warning("scope-fence: schema init failed: %s", e)
        raise
    _DB_LOCAL.conn = conn
    return conn


def _ensure_schema(conn):
    """Create tables if they don't exist (idempotent)."""
    conn.execute("""CREATE TABLE IF NOT EXISTS scopes (
        session_id TEXT NOT NULL,
        path TEXT NOT NULL,
        added_at REAL NOT NULL,
        PRIMARY KEY (session_id, path)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cwd_state (
        session_id TEXT PRIMARY KEY,
        cwd TEXT,
        updated_at REAL NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        ts REAL NOT NULL,
        tool TEXT NOT NULL,
        target TEXT NOT NULL,
        reason TEXT NOT NULL,
        blocked INTEGER NOT NULL DEFAULT 1,
        command TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS session_alias (
        session_id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL
    )""")
    conn.commit()


def resolve_keys(session_id: str, conversation_id: str = "") -> list[str]:
    """Return all keys related to a session/conversation (deduped, non-empty)."""
    keys = []
    if conversation_id:
        keys.append(conversation_id)
    if session_id:
        keys.append(session_id)
    # Add aliased keys
    conn = _get_db()
    for sid in (session_id, conversation_id):
        if sid:
            try:
                rows = conn.execute(
                    "SELECT session_id, conversation_id FROM session_alias WHERE session_id = ? OR conversation_id = ?",
                    (sid, sid)).fetchall()
                for r in rows:
                    for k in (r[0], r[1]):
                        if k and k not in keys:
                            keys.append(k)
            except Exception:
                pass
    return keys


def _primary_key(session_id: str, conversation_id: str = "") -> str:
    """Return the primary key for state storage."""
    if conversation_id:
        return conversation_id
    if session_id:
        return session_id
    return ""


def get_scope(session_id: str, conversation_id: str = "") -> dict:
    """Get scope for session/conversation. Returns {"roots": [Path], "deny": [Path], "cwd": str or None}."""
    pk = _primary_key(session_id, conversation_id)
    if not pk:
        from .config import load_config
        cfg = load_config()
        deny = [os.path.expanduser(p) for p in cfg["deny_paths"]]
        from .paths import resolve
        deny = [resolve(str(p)) for p in deny]
        return {"roots": [], "deny": deny, "cwd": None}

    # Always record the session_id <-> conversation_id alias BEFORE the cache
    # lookup, so a cache hit never skips alias creation.
    if session_id and conversation_id and session_id != conversation_id:
        try:
            _conn = _get_db()
            _conn.execute("INSERT OR REPLACE INTO session_alias (session_id, conversation_id) VALUES (?, ?)",
                          (session_id, conversation_id))
            _conn.commit()
        except Exception:
            pass

    with _CACHE_LOCK:
        if pk in _CACHE:
            return _CACHE[pk]

    from .config import load_config
    cfg = load_config()
    deny = [os.path.expanduser(p) for p in cfg["deny_paths"]]
    from .paths import resolve
    deny = [resolve(str(p)) for p in deny]

    conn = _get_db()
    keys = resolve_keys(session_id, conversation_id)
    roots = []
    cwd = None

    for key in keys:
        rows = conn.execute("SELECT path FROM scopes WHERE session_id = ?", (key,)).fetchall()
        for r in rows:
            rp = resolve(r[0])
            if rp not in roots:
                roots.append(rp)
        if cwd is None:
            cwd_row = conn.execute("SELECT cwd FROM cwd_state WHERE session_id = ?", (key,)).fetchone()
            if cwd_row and cwd_row[0]:
                cwd = cwd_row[0]

    # Backfill: if conversation_id has no scope but session_id does, adopt it
    if conversation_id and session_id and session_id != pk and not roots:
        rows = conn.execute("SELECT path FROM scopes WHERE session_id = ?", (session_id,)).fetchall()
        if rows:
            now = time.time()
            for (p,) in rows:
                conn.execute("INSERT OR IGNORE INTO scopes (session_id, path, added_at) VALUES (?, ?, ?)",
                             (pk, p, now))
            try:
                conn.execute("INSERT OR REPLACE INTO session_alias (session_id, conversation_id) VALUES (?, ?)",
                             (session_id, conversation_id))
            except sqlite3.OperationalError:
                pass
            conn.commit()
            roots = [resolve(r[0]) for r in rows]
        if cwd is None:
            cwd_row = conn.execute("SELECT cwd FROM cwd_state WHERE session_id = ?", (session_id,)).fetchone()
            if cwd_row and cwd_row[0]:
                cwd = cwd_row[0]
                conn.execute("INSERT OR REPLACE INTO cwd_state (session_id, cwd, updated_at) VALUES (?, ?, ?)",
                             (pk, cwd, time.time()))
                try:
                    conn.execute("INSERT OR REPLACE INTO session_alias (session_id, conversation_id) VALUES (?, ?)",
                                 (session_id, conversation_id))
                except sqlite3.OperationalError:
                    pass
                conn.commit()

    scope = {"roots": roots, "deny": deny, "cwd": cwd}
    # Only cache non-empty scopes (avoid stale empty cache)
    if roots:
        with _CACHE_LOCK:
            _CACHE[pk] = scope
    return scope


def invalidate_related(session_id: str, conversation_id: str = ""):
    """Invalidate cache for all keys related to session/conversation."""
    for key in resolve_keys(session_id, conversation_id):
        with _CACHE_LOCK:
            _CACHE.pop(key, None)


def invalidate_cache(session_id: str, conversation_id: str = ""):
    """Invalidate in-memory cache (alias for invalidate_related)."""
    invalidate_related(session_id, conversation_id)


def add_scope(session_id: str, paths: list, conversation_id: str = ""):
    """Add paths to scope for session/conversation."""
    pk = _primary_key(session_id, conversation_id) or session_id
    if not pk:
        return
    conn = _get_db()
    now = time.time()
    for p in paths:
        conn.execute("INSERT OR IGNORE INTO scopes (session_id, path, added_at) VALUES (?, ?, ?)",
                     (pk, str(p), now))
    if session_id and conversation_id and session_id != conversation_id:
        try:
            conn.execute("INSERT OR REPLACE INTO session_alias (session_id, conversation_id) VALUES (?, ?)",
                         (session_id, conversation_id))
        except sqlite3.OperationalError:
            pass
    conn.commit()
    invalidate_related(session_id, conversation_id)


def remove_scope(session_id: str, path: str, conversation_id: str = ""):
    """Remove a path from scope across all related keys."""
    from .paths import resolve
    resolved = str(resolve(path))
    conn = _get_db()
    keys = resolve_keys(session_id, conversation_id)
    if not keys:
        keys = [session_id]
    for key in keys:
        rows = conn.execute("SELECT path FROM scopes WHERE session_id = ?", (key,)).fetchall()
        for (p,) in rows:
            if str(resolve(p)) == resolved:
                conn.execute("DELETE FROM scopes WHERE session_id = ? AND path = ?", (key, p))
    conn.commit()
    invalidate_related(session_id, conversation_id)


def record_cwd(session_id: str, cwd: str, conversation_id: str = ""):
    """Record terminal CWD for session/conversation."""
    pk = _primary_key(session_id, conversation_id)
    if not pk:
        return
    conn = _get_db()
    now = time.time()
    conn.execute("INSERT OR REPLACE INTO cwd_state (session_id, cwd, updated_at) VALUES (?, ?, ?)",
                 (pk, cwd, now))
    conn.commit()
    invalidate_related(session_id, conversation_id)


def record_block(session_id: str, tool: str, target: str, reason: str, conversation_id: str = ""):
    """Record a blocked call in the audit log.

    The raw command is deliberately NOT stored (privacy). The `command` column
    exists in the schema for backward compatibility and is always NULL.
    """
    pk = _primary_key(session_id, conversation_id) or session_id
    if not pk:
        return
    conn = _get_db()
    now = time.time()
    conn.execute(
        'INSERT INTO audit (session_id, ts, tool, target, reason, blocked, command) VALUES (?, ?, ?, ?, ?, 1, ?)',
        (pk, now, tool, str(target)[:500], reason, None))
    conn.commit()


def get_audit(session_id: str, limit: int = 10, conversation_id: str = "") -> list:
    """Get recent audit entries across all related keys."""
    conn = _get_db()
    keys = resolve_keys(session_id, conversation_id)
    if not keys:
        keys = [session_id]
    results = []
    seen_ids = set()
    for key in keys:
        rows = conn.execute(
            "SELECT id, ts, tool, target, reason FROM audit WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
            (key, limit)).fetchall()
        for r in rows:
            if r[0] not in seen_ids:
                seen_ids.add(r[0])
                results.append({"ts": r[1], "tool": r[2], "target": r[3], "reason": r[4]})
    results.sort(key=lambda x: x["ts"], reverse=True)
    return results[:limit]


def prune_session(session_id: str, conversation_id: str = ""):
    """Delete this session's state; only delete shared conversation state if no
    other session is still aliased to it."""
    conn = _get_db()

    # Collect conversation keys aliased to this session BEFORE deleting aliases
    conv_keys = []
    if conversation_id:
        conv_keys.append(conversation_id)
    try:
        rows = conn.execute(
            "SELECT conversation_id FROM session_alias WHERE session_id = ?", (session_id,)).fetchall()
        for (cid,) in rows:
            if cid and cid not in conv_keys:
                conv_keys.append(cid)
    except sqlite3.OperationalError:
        pass

    # Delete the session's own rows
    conn.execute("DELETE FROM audit WHERE session_id = ?", (session_id,))
    conn.execute("DELETE FROM scopes WHERE session_id = ?", (session_id,))
    conn.execute("DELETE FROM cwd_state WHERE session_id = ?", (session_id,))
    try:
        conn.execute("DELETE FROM session_alias WHERE session_id = ?", (session_id,))
    except sqlite3.OperationalError:
        pass

    # Delete shared conversation rows only if no other session is aliased to them
    for ck in conv_keys:
        try:
            other = conn.execute(
                "SELECT session_id FROM session_alias WHERE conversation_id = ? AND session_id != ?",
                (ck, session_id)).fetchall()
        except sqlite3.OperationalError:
            other = []
        if not other:
            conn.execute("DELETE FROM audit WHERE session_id = ?", (ck,))
            conn.execute("DELETE FROM scopes WHERE session_id = ?", (ck,))
            conn.execute("DELETE FROM cwd_state WHERE session_id = ?", (ck,))
            try:
                conn.execute("DELETE FROM session_alias WHERE conversation_id = ?", (ck,))
            except sqlite3.OperationalError:
                pass

    conn.commit()
    invalidate_related(session_id, conversation_id)
