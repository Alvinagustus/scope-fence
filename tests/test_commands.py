"""Tests for commands module."""
import os
import sys
import tempfile
sys.path.insert(0, os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), "..")))

import scope_fence.store as store_mod
_tmpdir = tempfile.mkdtemp()


_DB_CONN = None


def _init_test_db():
    global _DB_CONN
    if _DB_CONN is not None:
        return _DB_CONN
    import sqlite3
    db_path = os.path.join(_tmpdir, "test_cmd.db")
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS scopes (session_id TEXT NOT NULL, path TEXT NOT NULL, added_at REAL NOT NULL, PRIMARY KEY (session_id, path))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cwd_state (session_id TEXT PRIMARY KEY, cwd TEXT, updated_at REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 1, command TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS session_alias (session_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL)""")
    conn.commit()
    _DB_CONN = conn
    return conn


store_mod._get_db = lambda hermes_home=None: _init_test_db()

from scope_fence.commands import handle_scope
from scope_fence.store import invalidate_cache, add_scope
from conftest import SCRATCH


def test_usage_no_args():
    sid = "cmd-1"
    invalidate_cache(sid)
    result = handle_scope("", sid)
    assert "Usage" in result


def test_add_absolute():
    sid = "cmd-2"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        result = handle_scope(f'add "{d}"', sid)
        assert "Scope Fence active" in result or "active" in result.lower()


def test_add_slash_rejected():
    sid = "cmd-3"
    invalidate_cache(sid)
    result = handle_scope("add /", sid)
    assert "allows everything" in result


def test_list():
    sid = "cmd-4"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        handle_scope(f'add "{d}"', sid)
        result = handle_scope("list", sid)
        assert "Scope" in result


def test_remove():
    sid = "cmd-5"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        handle_scope(f'add "{d}"', sid)
        result = handle_scope(f'remove "{d}"', sid)
        assert "Removed" in result


def test_check():
    sid = "cmd-6"
    invalidate_cache(sid)
    result = handle_scope("check", sid)
    assert "Scope Fence check" in result


def test_unknown_subcommand():
    sid = "cmd-7"
    invalidate_cache(sid)
    result = handle_scope("foo", sid)
    assert "Usage" in result


def test_windows_root_rejected():
    """FIX-6: Windows drive roots are rejected."""
    from scope_fence.commands import handle_scope
    sid = "win-root"
    result = handle_scope("add C:\\\\", session_id=sid)
    assert "allows everything" in result or "pick the project directory" in result


def test_posix_root_rejected():
    from scope_fence.commands import handle_scope
    sid = "posix-root"
    result = handle_scope("add /", session_id=sid)
    assert "allows everything" in result or "pick the project directory" in result
