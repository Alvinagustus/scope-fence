"""Slash command handler for /scope."""
import os
import shlex
import time

from .paths import resolve, is_filesystem_root, is_abs_path
from .store import get_scope, add_scope, remove_scope, get_audit, invalidate_cache
from .config import load_config, extra_write_roots

USAGE = ("Usage: /scope add <dir> [<dir> ...] | /scope list | "
         "/scope remove <dir> | /scope check | /scope doctor")

_is_filesystem_root = is_filesystem_root  # backwards-compatible alias


def _status_line(status: str, msg: str) -> str:
    return f"{status:<4} {msg}"


def _db_check():
    """Write/read/delete roundtrip on a scratch scope row. Returns (ok, error)."""
    try:
        from .store import _get_db
        conn = _get_db()
        probe = "__scope_fence_doctor_probe__"
        conn.execute("INSERT OR REPLACE INTO scopes (session_id, path, added_at) VALUES (?, ?, ?)",
                     (probe, "/tmp/probe", time.time()))
        row = conn.execute("SELECT path FROM scopes WHERE session_id = ?", (probe,)).fetchone()
        conn.execute("DELETE FROM scopes WHERE session_id = ?", (probe,))
        conn.commit()
        return (row is not None and row[0] == "/tmp/probe"), None
    except Exception as e:
        return False, str(e)[:200]


def _doctor(session_id: str) -> str:
    """One line per check: OK / WARN / FAIL. Never raises, never prints file contents."""
    lines = ["Scope Fence doctor:"]

    if session_id:
        lines.append(_status_line("OK", "command context provided a session_id"))
    else:
        lines.append(_status_line("WARN", "no session_id in command context — the fence cannot be scoped"))

    ok, err = _db_check()
    lines.append(_status_line("OK" if ok else "FAIL",
                              "plugin DB opens, schema exists, write/read/delete roundtrip works"
                              + ("" if ok else f" ({err})")))

    try:
        cfg = load_config()
        lines.append(_status_line("OK", "config loaded: "
                                  f"mode={cfg.get('mode')}, "
                                  f"extra_write_paths={cfg.get('extra_write_paths')}, "
                                  f"deny_paths={len(cfg.get('deny_paths', []))}, "
                                  f"auto_scope={cfg.get('auto_scope')}"))
    except Exception as e:
        lines.append(_status_line("FAIL", f"config load failed: {e}"))

    try:
        from .hooks import get_stats
        st = get_stats()
        lines.append(_status_line("OK", "hook counters since process start: "
                                  f"pre_tool_call={st.get('pre_tool_call')}, "
                                  f"with_session_id={st.get('with_session_id')}, "
                                  f"with_conversation_id={st.get('with_conversation_id')}, "
                                  f"with_neither={st.get('with_neither')}, "
                                  f"post_compaction={st.get('post_compaction')}, "
                                  f"section_render={st.get('section_render')}"))
    except Exception as e:
        lines.append(_status_line("FAIL", f"hook counters unavailable: {e}"))

    try:
        from .hooks import get_breaker_state
        br = get_breaker_state()
        status = "WARN" if br.get("open") else "OK"
        msg = f"breaker {'OPEN' if br.get('open') else 'closed'} (consecutive errors={br.get('errors')})"
        if br.get("last_error"):
            msg += f" — last error: {br.get('last_error')}"
        lines.append(_status_line(status, msg))
    except Exception as e:
        lines.append(_status_line("FAIL", f"breaker state unavailable: {e}"))

    try:
        scope = get_scope(session_id)
        roots = ", ".join(str(p) for p in scope["roots"]) or "(none)"
        cwd = scope.get("cwd") or "(unknown)"
        lines.append(_status_line("OK", f"scope roots: {roots}"))
        lines.append(_status_line("OK", f"tracked cwd: {cwd}"))
    except Exception as e:
        lines.append(_status_line("FAIL", f"scope unavailable: {e}"))

    return "\n".join(lines)


def _add(session_id: str, paths: list) -> str:
    cfg = load_config()
    max_paths = cfg.get("max_scope_paths", 8)
    scope = get_scope(session_id)

    resolved_paths = []
    warnings = []
    for p in paths:
        if len(scope["roots"]) + len(resolved_paths) >= max_paths:
            return f"⛔ Max {max_paths} scope paths reached."
        rp = resolve(p, scope["cwd"])
        # Reject filesystem roots (POSIX / and Windows C:\ or UNC)
        if is_filesystem_root(p) or is_filesystem_root(rp):
            return "⛔ A scope of a filesystem root allows everything — pick the project directory."
        if str(rp) == os.path.expanduser("~") or str(rp) == os.path.realpath(os.path.expanduser("~")):
            warnings.append(f"⚠️ Scoping to $HOME means the deny-list does all the work: {rp}")
        # Relative path with no tracked CWD
        if not is_abs_path(p) and not scope["cwd"]:
            return "⛔ Relative path with no tracked CWD. Give an absolute path, or run a terminal command first."
        resolved_paths.append(str(rp))

    if resolved_paths:
        add_scope(session_id, resolved_paths)
        scope = get_scope(session_id)
        lines = ["✅ Scope Fence active."]
        lines.append(f"Scope: {', '.join(str(p) for p in scope['roots'])}")
        lines.append(f"Deny-list: {', '.join(cfg['deny_paths'])}")
        if warnings:
            lines.extend(warnings)
        return "\n".join(lines)
    return USAGE


def _scratch_line() -> str:
    try:
        extra = extra_write_roots()
        if extra:
            return f"Scratch paths (writable): {', '.join(str(p) for p in extra)}"
    except Exception:
        pass
    return ""


def _list(session_id: str) -> str:
    scope = get_scope(session_id)
    cfg = load_config()
    lines = ["Scope Fence status:"]
    lines.append(f"Mode: {cfg.get('mode', 'enforce')}")
    if scope["roots"]:
        lines.append("Active: yes")
        lines.append(f"Scope: {', '.join(str(p) for p in scope['roots'])}")
    else:
        lines.append("Active: no (no scope declared)")
    scratch = _scratch_line()
    if scratch:
        lines.append(scratch)
    lines.append(f"Deny-list: {', '.join(cfg['deny_paths'])}")
    if scope["cwd"]:
        lines.append(f"Tracked CWD: {scope['cwd']}")
    return "\n".join(lines)


def _remove(session_id: str, path: str) -> str:
    scope = get_scope(session_id)
    rp = resolve(path, scope["cwd"])
    remove_scope(session_id, str(rp))
    scope = get_scope(session_id)
    if scope["roots"]:
        return f"✅ Removed {rp}. Scope: {', '.join(str(p) for p in scope['roots'])}"
    return f"✅ Removed {rp}. No scope remaining — fence inactive."


def _audit_tag(reason: str) -> str:
    """Classify an audit row: WARN (would-block), BLOCK (real block), INFO/ERR (other)."""
    r = str(reason)
    if r.startswith("would-block:"):
        return "WARN"
    if r == "auto-scope" or r.startswith("auto-scope:"):
        return "INFO"
    if r in ("breaker-open", "hook-error"):
        return "ERR"
    return "BLOCK"


def _check(session_id: str) -> str:
    scope = get_scope(session_id)
    cfg = load_config()
    lines = ["Scope Fence check:"]
    lines.append(f"Mode: {cfg.get('mode', 'enforce')}")
    if scope["roots"]:
        lines.append("Active: yes")
        lines.append(f"Scope: {', '.join(str(p) for p in scope['roots'])}")
    else:
        lines.append("Active: no")
    scratch = _scratch_line()
    if scratch:
        lines.append(scratch)
    lines.append(f"Deny-list: {', '.join(cfg['deny_paths'])}")
    if scope["cwd"]:
        lines.append(f"Tracked CWD: {scope['cwd']}")
    else:
        lines.append("Tracked CWD: (unknown)")
    # Audit
    audit = get_audit(session_id, limit=50)
    if audit:
        counts = {"WARN": 0, "BLOCK": 0, "INFO": 0, "ERR": 0}
        for a in audit:
            counts[_audit_tag(a["reason"])] += 1
        info = counts["INFO"] + counts["ERR"]
        lines.append(f"\nSummary: {counts['WARN']} would-block, {counts['BLOCK']} blocked, "
                     f"{info} info (last session)")
        auto = [a for a in audit
                if str(a["reason"]) == "auto-scope" or str(a["reason"]).startswith("auto-scope:")]
        if auto:
            lines.append(f"Scope engaged automatically: {auto[0]['target']}")
        lines.append(f"Recent entries ({len(audit)}):")
        for a in audit:
            lines.append(f"  [{_audit_tag(a['reason'])}] [{a['tool']}] {a['target']} — {a['reason']}")
    else:
        lines.append("\nNo blocks recorded.")
    return "\n".join(lines)


def handle_scope(raw_args: str, session_id: str = "") -> str:
    """fn(raw_args: str) -> str — handlers must RETURN text, not print().
    Accepts optional session_id keyword from the command dispatch context."""
    try:
        toks = shlex.split(raw_args or "")
    except ValueError:
        return USAGE
    if not toks:
        return USAGE
    sub, rest = toks[0], toks[1:]
    if sub in ("add", "remove") and not session_id:
        return "⛔ Scope Fence: no session context — refusing to modify scope. Run this from a normal chat session."
    if sub == "add" and rest:
        return _add(session_id, rest)
    if sub == "list":
        return _list(session_id)
    if sub == "remove" and len(rest) == 1:
        return _remove(session_id, rest[0])
    if sub == "check":
        return _check(session_id)
    if sub == "doctor":
        return _doctor(session_id)
    return USAGE
