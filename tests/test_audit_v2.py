"""Regression tests for AUDIT-v2 findings (H-1, H-2, M-1, M-2, M-3, M-4, L-2, L-7)."""
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
    conn = sqlite3.connect(os.path.join(_tmpdir, "test.db"))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS scopes (session_id TEXT NOT NULL, path TEXT NOT NULL, added_at REAL NOT NULL, PRIMARY KEY (session_id, path))")
    conn.execute("CREATE TABLE IF NOT EXISTS cwd_state (session_id TEXT PRIMARY KEY, cwd TEXT, updated_at REAL NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 1, command TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS session_alias (session_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL)")
    conn.commit()
    _DB_CONN = conn
    return conn


store_mod._get_db = lambda hermes_home=None: _init_test_db()

from scope_fence.terminal import classify_terminal
from scope_fence.paths import is_inside, resolve
from scope_fence.hooks import on_pre_tool_call
from scope_fence.store import add_scope, invalidate_cache

PROJ = "/work/proj"


# --------------------------------------------------------------------------- H-1

def test_h1_flag_before_c_blocked():
    """H-1: a flag before -c must not defeat sh -c unwrapping."""
    for cmd in [
        "bash -i -c 'rm -rf /outside/x'",
        "bash --noprofile -c 'rm -rf /outside/x'",
        "sh -x -c 'rm -rf /outside/x'",
        "env FOO=bar bash -i -c 'rm -rf /outside/x'",
        "bash -lc 'rm -rf /outside/x'",
    ]:
        v, d = classify_terminal(cmd, workdir=PROJ)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            assert any(not is_inside(resolve(str(p)), [resolve(PROJ)]) for p in paths), f"should find a path outside the scope: {cmd}"


def test_h1_flag_before_c_readonly_allowed():
    """H-1 control: a read-only script through a flagged -c stays allowed."""
    v, _ = classify_terminal("bash -i -c 'echo hi'", workdir=PROJ)
    assert v == "allow"


# --------------------------------------------------------------------------- M-2

def test_m2_destructive_inside_substitution_blocked():
    """M-2: a destructive command inside $(...)/backticks is classified."""
    for cmd in [
        "echo $(rm -rf /outside/x)",
        "echo $(rm -rf /outside/x; echo done)",
        "echo `rm -rf /outside/x`",
    ]:
        v, d = classify_terminal(cmd, workdir=PROJ)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"


def test_m2_readonly_substitution_allowed():
    """M-2 control: read-only inner commands stay allowed (no false positive).

    The classifier may return "check" for the substitution text, but every resolved
    operand must stay inside the scope (the hook then allows the call).
    """
    for cmd in [
        "echo $(date)",
        "echo $(basename /etc/passwd)",
        "git commit -m \"$(cat msg.txt)\"",
        "ls $(echo foo)",
    ]:
        v, d = classify_terminal(cmd, workdir=PROJ)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            assert all(is_inside(resolve(str(p)), [resolve(PROJ)]) for p in paths), \
                f"check operands must stay in scope: {cmd} ({paths})"
        else:
            assert v == "allow", f"should allow: {cmd} (got {v})"


# --------------------------------------------------------------------------- M-3

def test_m3_compact_short_option_blocked():
    """M-3: -o/path and -O/path operands are extracted."""
    for cmd in [
        "curl -o/outside/x https://example.com",
        "wget -O/outside/x https://example.com",
    ]:
        v, d = classify_terminal(cmd, workdir=PROJ)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            assert any(not is_inside(resolve(str(p)), [resolve(PROJ)]) for p in paths), f"should find a path outside the scope: {cmd}"


def test_m3_short_flag_cluster_allowed():
    """M-3 control: a short flag cluster without a path value is not a path."""
    v, _ = classify_terminal("rm -rf /work/proj/build", workdir=PROJ)
    assert v in ("allow", "check")


# --------------------------------------------------------------------------- H-2

def _fresh(sid, roots):
    invalidate_cache(sid)
    add_scope(sid, roots)
    invalidate_cache(sid)


def test_h2_move_file_header_blocked():
    """H-2: the real V4A `*** Move File: a -> b` header is parsed; destination is checked."""
    home = os.path.realpath(os.path.expanduser("~"))
    sid = "audit-h2"
    _fresh(sid, [home])
    r = on_pre_tool_call(
        tool_name="patch",
        args={
            "patch": "*** Begin Patch\n*** Move File: " + home + "/a.txt -> /outside/b.txt\n*** End Patch",
            "path": home + "/a.txt",
        },
        session_id=sid,
    )
    assert r is not None and r["action"] == "block", "move destination outside scope must block"


def test_h2_move_file_inside_scope_allowed():
    """H-2 control: a move with both sides inside scope is allowed."""
    home = os.path.realpath(os.path.expanduser("~"))
    sid = "audit-h2-ok"
    _fresh(sid, [home])
    r = on_pre_tool_call(
        tool_name="patch",
        args={
            "patch": "*** Begin Patch\n*** Move File: " + home + "/a.txt -> " + home + "/b.txt\n*** End Patch",
            "path": home + "/a.txt",
        },
        session_id=sid,
    )
    assert r is None, f"in-scope move should pass, got {r}"


# --------------------------------------------------------------------------- M-1

def test_m1_skill_manage_exempt_from_hermes_deny():
    """M-1: skill_manage is exempt from the ~/.hermes deny entry."""
    import scope_fence.config as cfg_mod
    old = dict(cfg_mod._RUNTIME_CONFIG)
    try:
        cfg_mod.set_runtime_config({"allow_skill_writes": True})
        sid = "audit-m1"
        _fresh(sid, [PROJ])
        r = on_pre_tool_call(
            tool_name="skill_manage",
            args={"action": "create", "name": "evil-skill"},
            session_id=sid,
        )
        assert r is None, f"skill_manage with allow_skill_writes should pass, got {r}"
    finally:
        cfg_mod.set_runtime_config(old)


def test_m1_write_file_to_hermes_still_denied():
    """M-1 control: raw write_file to ~/.hermes is still denied."""
    sid = "audit-m1-deny"
    _fresh(sid, [PROJ])
    r = on_pre_tool_call(tool_name="write_file", args={"path": "~/.hermes/x"}, session_id=sid)
    assert r is not None and r["action"] == "block"
    assert "deny-list" in r["message"]


# --------------------------------------------------------------------------- L-2

def test_l2_echo_deny_listed_path_allowed():
    """L-2: mentioning a deny-listed path (echo) is not reading/writing it."""
    sid = "audit-l2"
    _fresh(sid, [PROJ])
    r = on_pre_tool_call(tool_name="terminal", args={"command": "echo ~/.ssh/id_rsa"}, session_id=sid)
    assert r is None, f"echo of a path should pass, got {r}"


def test_l2_cat_deny_listed_path_blocked():
    """L-2 control: reading a deny-listed path is still blocked."""
    sid = "audit-l2-cat"
    _fresh(sid, [PROJ])
    r = on_pre_tool_call(tool_name="terminal", args={"command": "cat ~/.ssh/id_rsa"}, session_id=sid)
    assert r is not None and r["action"] == "block"
    assert "deny-list" in r["message"]


# --------------------------------------------------------------------------- M-4 / L-7

def test_m4_no_broken_entry_point():
    """M-4: no pyproject.toml ships — the plugin is directory-installed, so there is no
    pip entry point to get wrong."""
    root = os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), ".."))
    assert not os.path.exists(os.path.join(root, "pyproject.toml")), \
        "pyproject.toml should not ship (the entry point is repo-root __init__.py)"


def test_l7_manifest_declares_kind():
    """L-7: plugin.yaml declares kind: standalone."""
    root = os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), ".."))
    text = open(os.path.join(root, "plugin.yaml")).read()
    assert "kind: standalone" in text
