"""Tests for hooks module."""
import os
import sys
import tempfile
sys.path.insert(0, os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), "..")))

# Mock store to use temp db
import scope_fence.store as store_mod
_tmpdir = tempfile.mkdtemp()
store_mod._get_db = lambda hermes_home=None: _init_test_db()


_DB_CONN = None


def _init_test_db():
    global _DB_CONN
    if _DB_CONN is not None:
        return _DB_CONN
    import sqlite3
    db_path = os.path.join(_tmpdir, "test.db")
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS scopes (session_id TEXT NOT NULL, path TEXT NOT NULL, added_at REAL NOT NULL, PRIMARY KEY (session_id, path))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cwd_state (session_id TEXT PRIMARY KEY, cwd TEXT, updated_at REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 1, command TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS session_alias (session_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL)""")
    conn.commit()
    return conn


from scope_fence.hooks import on_pre_tool_call, on_post_tool_call, on_session_finalize
from scope_fence.store import add_scope, invalidate_cache, get_scope
from conftest import SCRATCH


def test_fence_inactive_no_scope():
    sid = "test-inactive"
    invalidate_cache(sid)
    result = on_pre_tool_call(tool_name="write_file", args={"path": "/tmp/x"}, session_id=sid)
    assert result is None


def test_write_inside_scope():
    sid = "test-inside"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        result = on_pre_tool_call(tool_name="write_file", args={"path": os.path.join(d, "file.txt")}, session_id=sid)
        assert result is None


def test_write_outside_scope():
    sid = "test-outside"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d1:
        add_scope(sid, [d1])
        # /outside is outside scope and outside the default scratch paths (/tmp, ~/.cache)
        result = on_pre_tool_call(tool_name="write_file", args={"path": "/outside/file.txt"}, session_id=sid)
        assert result is not None
        assert result["action"] == "block"
        assert "outside-scope" in result["message"] or "outside" in result["message"]


def test_deny_list_hit():
    sid = "test-deny"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        ssh = os.path.join(d, ".ssh")
        os.makedirs(ssh, exist_ok=True)
        add_scope(sid, [d])
        # Manually add deny by patching scope
        from scope_fence.store import get_scope
        scope = get_scope(sid)
        from scope_fence.paths import resolve
        scope["deny"] = [resolve(ssh)]
        store_mod._CACHE[sid] = scope
        result = on_pre_tool_call(tool_name="write_file", args={"path": os.path.join(ssh, "id_rsa")}, session_id=sid)
        assert result is not None
        assert result["action"] == "block"


def test_never_raises():
    sid = "test-raises"
    invalidate_cache(sid)
    # Malformed args
    result = on_pre_tool_call(tool_name="write_file", args="not a dict", session_id=sid)
    assert result is None or result["action"] == "block"
    result = on_pre_tool_call(tool_name="write_file", args={}, session_id=sid)
    assert result is None or result["action"] == "block"


def test_terminal_unparseable():
    sid = "test-term"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        result = on_pre_tool_call(tool_name="terminal", args={"command": 'rm -rf "$TARGET"'}, session_id=sid)
        assert result is not None
        assert result["action"] == "block"
        assert "unparseable" in result["message"]


def test_post_tool_call_cwd():
    sid = "test-cwd"
    invalidate_cache(sid)
    import json
    result_str = json.dumps({"cwd": "/tmp/testcwd"})
    on_post_tool_call(tool_name="terminal", result=result_str, session_id=sid)
    from scope_fence.store import get_scope
    scope = get_scope(sid)
    assert scope["cwd"] == "/tmp/testcwd"


def test_on_session_finalize_deletes_scope():
    sid = "test-end"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
    on_session_finalize(session_id=sid)
    invalidate_cache(sid)
    from scope_fence.store import get_scope
    scope = get_scope(sid)
    assert not scope["roots"]


# --- Fix #2 regression tests ---

def test_terminal_normal_commands_inside_scope():
    """FIX-A: normal commands inside scope must not be blocked."""
    sid = "test-normal-inside"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        for cmd in ["mkdir build", "rm -rf file.txt", "echo hi > out.txt", "touch a.txt"]:
            result = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
            assert result is None or result.get("action") != "block", f"should allow: {cmd}"


def test_terminal_outside_scope_blocked():
    """FIX-A: destructive commands outside scope must be blocked."""
    sid = "test-outside-block"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        for cmd in ["rm -rf /outside", "echo hi > /outside/x"]:
            result = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
            assert result is not None and result["action"] == "block", f"should block: {cmd}"


def test_substitution_bypass_blocked():
    """C1: substitution in a WRITER segment is blocked; read-only commands pass."""
    sid = "test-subst"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        # Writers with substitution → block
        for cmd in ["rm -rf $(echo /outside)", "rm -rf `/bin/echo /outside`"]:
            result = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
            assert result is not None and result["action"] == "block", f"should block: {cmd}"
        # Read-only commands with substitution → allow
        for cmd in ["echo $(date)", "git commit -m \"$(cat msg.txt)\"", "ls $(echo foo)"]:
            result = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
            assert result is None or result.get("action") != "block", f"should allow: {cmd}"


def test_cache_invalidation_after_add():
    """FIX-C: /scope add must invalidate conversation cache."""
    sid = "test-cache-add"
    cid = "test-cache-conv"
    invalidate_cache(sid)
    invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        # Simulate tool call before scope is added (caches empty for conversation)
        on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=sid, conversation_id=cid)
        # Now add scope
        add_scope(sid, [d], conversation_id=cid)
        # Write outside scope must be blocked without manual invalidation
        result = on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=sid, conversation_id=cid)
        assert result is not None and result["action"] == "block"


def test_key_resolution_consistency():
    """FIX-D: remove_scope and audit work across session/conversation keys."""
    sid = "test-keys"
    cid = "test-keys-conv"
    invalidate_cache(sid)
    invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d], conversation_id=cid)
        invalidate_cache(sid)
        invalidate_cache(cid)
        from scope_fence.store import get_scope, get_audit, remove_scope
        # Scope visible via conversation key
        assert get_scope(sid, cid)["roots"]
        # remove_scope must clear it
        remove_scope(sid, d, conversation_id=cid)
        invalidate_cache(sid)
        invalidate_cache(cid)
        assert not get_scope(sid, cid)["roots"]


def test_audit_across_keys():
    """FIX-D: get_audit returns entries from all related keys."""
    sid = "test-audit"
    cid = "test-audit-conv"
    invalidate_cache(sid)
    invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d], conversation_id=cid)
        invalidate_cache(sid)
        invalidate_cache(cid)
        on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=sid, conversation_id=cid)
        from scope_fence.store import get_audit
        assert len(get_audit(sid, conversation_id=cid)) >= 1
        assert len(get_audit(sid)) >= 1


def test_finalize_cleans_all_keys():
    """FIX-D: on_session_finalize cleans session and conversation rows."""
    sid = "test-finalize"
    cid = "test-finalize-conv"
    invalidate_cache(sid)
    invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d], conversation_id=cid)
        on_session_finalize(session_id=sid, conversation_id=cid)
        invalidate_cache(sid)
        invalidate_cache(cid)
        from scope_fence.store import get_scope
        assert not get_scope(sid, cid)["roots"]
        assert not get_scope(sid)["roots"]


def test_relative_path_file_tool():
    """FIX-G: relative paths resolve against session cwd."""
    sid = "test-rel"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        from scope_fence.store import record_cwd
        record_cwd(sid, d)
        invalidate_cache(sid)
        result = on_pre_tool_call(tool_name="write_file", args={"path": "a.txt"}, session_id=sid)
        assert result is None or result.get("action") != "block"
        result = on_pre_tool_call(tool_name="write_file", args={"path": "../../outside.txt"}, session_id=sid)
        assert result is not None and result["action"] == "block"


def test_glob_and_url_allowed():
    """FIX-F: globs and URLs must not be blocked."""
    sid = "test-glob"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        for cmd in ["find . -name '*.py'", "curl 'https://x?a=b'"]:
            result = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
            assert result is None or result.get("action") != "block", f"should allow: {cmd}"


def test_git_reset_inside_scope_allowed():
    """FIX-F: git reset --hard inside scope is allowed (non-strict)."""
    sid = "test-git-reset"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        result = on_pre_tool_call(tool_name="terminal", args={"command": "git reset --hard", "workdir": d}, session_id=sid)
        assert result is None or result.get("action") != "block"


def test_git_branch_delete_blocked():
    """FIX-F: git branch -D is blocked."""
    sid = "test-git-branch"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        result = on_pre_tool_call(tool_name="terminal", args={"command": "git branch -D main", "workdir": d}, session_id=sid)
        assert result is not None and result["action"] == "block"


# --- Fix #3 regression tests ---

def test_alias_created_without_conv_in_add():
    """FIX-2: alias is created when get_scope sees both session and conversation."""
    sid, cid = "alias-A", "alias-C"
    invalidate_cache(sid); invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])  # no conversation_id, like /scope add
        s = get_scope(sid, cid)
        assert s["roots"]
        from scope_fence.store import _get_db
        conn = _get_db()
        rows = conn.execute("SELECT * FROM session_alias WHERE session_id = ?", (sid,)).fetchall()
        assert rows, "alias should be created"


def test_audit_visible_via_session_key():
    """FIX-2: audit written under conversation key is visible via session key."""
    sid, cid = "audit-A", "audit-C"
    invalidate_cache(sid); invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        get_scope(sid, cid)
        on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=sid, conversation_id=cid)
        from scope_fence.store import get_audit
        assert len(get_audit(sid)) >= 1


def test_remove_scope_clears_all_keys():
    """FIX-2: remove_scope clears session and conversation keys."""
    sid, cid = "rm-A", "rm-C"
    invalidate_cache(sid); invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        get_scope(sid, cid)
        from scope_fence.store import remove_scope, get_scope as _gs
        remove_scope(sid, d)
        invalidate_cache(sid); invalidate_cache(cid)
        assert not _gs(sid, cid)["roots"]
        assert not _gs(sid)["roots"]


def test_prune_clears_audit_and_alias():
    """FIX-2: prune_session removes scopes, cwd, audit, and alias rows."""
    sid, cid = "prune-A", "prune-C"
    invalidate_cache(sid); invalidate_cache(cid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        get_scope(sid, cid)
        on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=sid, conversation_id=cid)
        from scope_fence.store import prune_session, _get_db
        prune_session(sid)
        conn = _get_db()
        for table in ("scopes", "cwd_state", "audit"):
            rows = conn.execute(f"SELECT * FROM {table} WHERE session_id IN (?, ?)", (sid, cid)).fetchall()
            assert not rows, f"{table} should be empty"
        alias = conn.execute("SELECT * FROM session_alias WHERE session_id = ?", (sid,)).fetchall()
        assert not alias


def test_post_tool_call_result_dict_and_workdir():
    """FIX-4: cwd recorded from result dict and args.workdir."""
    sid = "cwd-dict"
    invalidate_cache(sid)
    on_post_tool_call(tool_name="terminal", result={"cwd": "/x"}, session_id=sid)
    from scope_fence.store import get_scope
    assert get_scope(sid)["cwd"] == "/x"

    sid2 = "cwd-workdir"
    invalidate_cache(sid2)
    on_post_tool_call(tool_name="terminal", result={}, args={"workdir": "/y"}, session_id=sid2)
    assert get_scope(sid2)["cwd"] == "/y"


def test_post_tool_call_no_cwd_no_change():
    """FIX-4: empty result/args must not overwrite known cwd."""
    sid = "cwd-keep"
    invalidate_cache(sid)
    on_post_tool_call(tool_name="terminal", result={"cwd": "/known"}, session_id=sid)
    on_post_tool_call(tool_name="terminal", result={}, args={}, session_id=sid)
    from scope_fence.store import get_scope
    assert get_scope(sid)["cwd"] == "/known"


def test_block_unparseable_destructive_config():
    """FIX-5: block_unparseable_destructive=false allows non-destructive unparseable."""
    import scope_fence.config as cfg_mod
    sid = "unparse-cfg"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        old = dict(cfg_mod._RUNTIME_CONFIG)
        try:
            cfg_mod.set_runtime_config({"block_unparseable_destructive": False})
            # non-destructive unparseable (substitution in echo) -> allow
            r = on_pre_tool_call(tool_name="terminal", args={"command": "echo $(date)", "workdir": d}, session_id=sid)
            assert r is None or r.get("action") != "block"
            # destructive unparseable -> still block
            r = on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf $(echo /outside)", "workdir": d}, session_id=sid)
            assert r is not None and r["action"] == "block"
        finally:
            cfg_mod.set_runtime_config(old)


# --- Fix #4 regression tests: cross-session prune ---

def test_prune_subagent_keeps_parent_scope():
    """FIX-3: finalize subagent must not delete shared conversation scope."""
    A, B, C = "prune-A", "prune-B", "prune-C"
    invalidate_cache(A); invalidate_cache(B); invalidate_cache(C)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(A, [d], conversation_id=C)
        invalidate_cache(A); invalidate_cache(C)
        # cold-cache get_scope(B, C) creates alias (B, C)
        get_scope(B, C)
        invalidate_cache(B)
        from scope_fence.store import prune_session
        prune_session(B)
        invalidate_cache(A); invalidate_cache(B); invalidate_cache(C)
        # Parent scope must survive
        assert get_scope(A, C)["roots"], "parent scope should survive subagent prune"
        result = on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"},
                                  session_id=A, conversation_id=C)
        assert result is not None and result["action"] == "block"


def test_prune_full_session_clears_shared():
    """FIX-3: finalizing the last session clears shared conversation state."""
    A, C = "prune2-A", "prune2-C"
    invalidate_cache(A); invalidate_cache(C)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(A, [d], conversation_id=C)
        get_scope(A, C)
        from scope_fence.store import prune_session, _get_db
        prune_session(A, C)
        conn = _get_db()
        for table in ("scopes", "cwd_state", "audit"):
            rows = conn.execute(f"SELECT * FROM {table} WHERE session_id IN (?, ?)", (A, C)).fetchall()
            assert not rows, f"{table} should be empty"


def test_audit_keep_removed_from_config():
    """FIX-5: audit_keep is no longer a config key (audit is cleared on finalize)."""
    import scope_fence.config as cfg_mod
    assert "audit_keep" not in cfg_mod.DEFAULTS
    assert "audit_keep" not in cfg_mod.CONFIG_SCHEMA
    # FIX-7: also removed from the register() CONFIG_KEYS
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location(
        "scope_fence_plugin_root",
        os.path.join(os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), "..")), "__init__.py"),
        submodule_search_locations=[os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), ".."))],
    )
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    assert "audit_keep" not in _mod.CONFIG_KEYS


# --- v8 regression tests (A/B/C/D/G) ---

def test_newline_separator_blocked():
    """A1: newline separates commands."""
    sid = "v8-a1"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="terminal", args={"command": "ls -la\nrm -rf /outside/x", "workdir": d}, session_id=sid)
        assert r is not None and r["action"] == "block"


def test_single_ampersand_blocked():
    """A2: single & separates commands."""
    sid = "v8-a2"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="terminal", args={"command": "ls & rm -rf /outside/x", "workdir": d}, session_id=sid)
        assert r is not None and r["action"] == "block"


def test_bash_c_then_command_blocked():
    """A3: bash -c wrapper followed by more commands."""
    sid = "v8-a3"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="terminal", args={"command": 'bash -c "ls" ; rm -rf /outside/x', "workdir": d}, session_id=sid)
        assert r is not None and r["action"] == "block"


def test_quoted_cd_blocked():
    """A4: quoted cd into outside dir."""
    sid = "v8-a4"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="terminal", args={"command": 'cd "/outside" && rm x', "workdir": d}, session_id=sid)
        assert r is not None and r["action"] == "block"


def test_variable_cd_blocked():
    """A5: cd $VAR marks cwd unknown; later writer blocked."""
    sid = "v8-a5"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="terminal", args={"command": 'cd "$DIR" && rm x', "workdir": d}, session_id=sid)
        assert r is not None and r["action"] == "block"


def test_skill_manage_create_blocked():
    """B1: skill_manage create without file_path resolves to skills root."""
    sid = "v8-b1"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="skill_manage", args={"action": "create", "name": "x", "content": "..."}, session_id=sid)
        assert r is not None and r["action"] == "block"


def test_patch_move_to_blocked():
    """B2/H-2: the real V4A `*** Move File: a -> b` header is parsed and both sides checked.

    Hermes parses `*** Move File: a -> b` (tools/patch_parser.py,
    tools/file_tools.py); there is no `*** Move to:` form anywhere in the codebase.
    The destination is an absolute path outside the scope, and the assertion checks the
    reason string so the test cannot pass vacuously.
    """
    sid = "v8-b2"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        outside = "/outside/moved.txt"
        r = on_pre_tool_call(
            tool_name="patch",
            args={"patch": f"*** Begin Patch\n*** Move File: {d}/a.txt -> {outside}\n*** End Patch",
                  "path": f"{d}/a.txt"},
            session_id=sid,
        )
        assert r is not None and r["action"] == "block", "move destination outside scope must block"
        assert "outside-scope" in r["message"], f"expected outside-scope, got: {r['message']}"


def test_substitution_only_blocks_writers():
    """C1: substitution blocks writers, not read-only commands."""
    sid = "v8-c1"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf $(echo /outside)", "workdir": d}, session_id=sid)
        assert r is not None and r["action"] == "block"
        r = on_pre_tool_call(tool_name="terminal", args={"command": "echo $(date)", "workdir": d}, session_id=sid)
        assert r is None or r.get("action") != "block"


def test_strict_mode_per_segment():
    """C5: strict mode blocks destructive commands in any segment."""
    import scope_fence.config as cfg_mod
    sid = "v8-c5"
    invalidate_cache(sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(sid, [d])
        invalidate_cache(sid)
        old = dict(cfg_mod._RUNTIME_CONFIG)
        try:
            cfg_mod.set_runtime_config({"strict_mode": True})
            for cmd in ["rm -rf build", "cd . && rm -rf build", "ls; rm -rf build"]:
                r = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
                assert r is not None and r["action"] == "block", f"strict should block: {cmd}"
            for cmd in ["python3 -m pytest", "find . -name x"]:
                r = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": d}, session_id=sid)
                assert r is None or r.get("action") != "block", f"strict should allow: {cmd}"
        finally:
            cfg_mod.set_runtime_config(old)


def test_empty_session_add_refused():
    """D1: /scope add with empty session_id is refused."""
    from scope_fence.commands import handle_scope
    result = handle_scope("add /tmp/proj", session_id="")
    assert "no session" in result.lower() or "refusing" in result.lower()


def test_deny_paths_additive():
    """D5: user deny_paths are additive over defaults by default."""
    import scope_fence.config as cfg_mod
    old = dict(cfg_mod._RUNTIME_CONFIG)
    try:
        cfg_mod.set_runtime_config({"deny_paths": ["/tmp/deny"]})
        cfg = cfg_mod.load_config()
        assert "/tmp/deny" in cfg["deny_paths"]
        assert "~/.ssh" in cfg["deny_paths"]
        cfg_mod.set_runtime_config({"deny_paths": ["/tmp/deny"], "replace_default_deny": True})
        cfg = cfg_mod.load_config()
        assert cfg["deny_paths"] == ["/tmp/deny"]
    finally:
        cfg_mod.set_runtime_config(old)


def test_compaction_copies_scope():
    """G1: post_compaction copies scope from old session id."""
    from scope_fence.hooks import on_post_compaction
    old_sid, new_sid = "v8-old", "v8-new"
    invalidate_cache(old_sid)
    invalidate_cache(new_sid)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        add_scope(old_sid, [d])
        invalidate_cache(old_sid)
        on_post_compaction(session_id=new_sid, old_session_id=old_sid)
        invalidate_cache(new_sid)
        from scope_fence.store import get_scope
        assert get_scope(new_sid)["roots"]
        r = on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=new_sid)
        assert r is not None and r["action"] == "block"


# --- Audit report regression tests ---

def test_terminal_deny_list_regex_fix():
    """F2: terminal deny-list path extraction must catch ~/.ssh paths."""
    import os
    home = os.path.realpath(os.path.expanduser("~"))
    sid = "audit-f2"
    invalidate_cache(sid)
    add_scope(sid, [home])  # scope = HOME so only the deny-list protects ~/.ssh
    invalidate_cache(sid)
    r = on_pre_tool_call(tool_name="terminal", args={"command": "tee ~/.ssh/authorized_keys", "workdir": home}, session_id=sid)
    assert r is not None and r["action"] == "block"
    assert "deny-list" in r["message"]


def test_auto_scope_under_home():
    """F5: auto-scope works for project directories under $HOME."""
    import os, subprocess, shutil
    home = os.path.realpath(os.path.expanduser("~"))
    repo = os.path.join(home, ".scope-fence-audit-repo")
    os.makedirs(repo, exist_ok=True)
    try:
        subprocess.run(["git", "init", "-q"], cwd=repo, capture_output=True)
        from scope_fence.store import record_cwd
        sid = "audit-f5"
        invalidate_cache(sid)
        record_cwd(sid, repo)
        invalidate_cache(sid)
        r = on_pre_tool_call(tool_name="write_file", args={"path": "/outside/evil"}, session_id=sid)
        assert r is not None and r["action"] == "block"
        from scope_fence.store import get_scope
        assert get_scope(sid)["roots"]
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_unknown_config_key_warns(caplog=None):
    """F15: unknown config keys are logged, not silently ignored."""
    import logging
    import scope_fence.config as cfg_mod
    old = dict(cfg_mod._RUNTIME_CONFIG)
    try:
        with __import__("unittest").TestCase().assertLogs("scope_fence.config", level="WARNING") as cm:
            cfg_mod.set_runtime_config({"deny_path": ["/tmp/x"]})  # typo
            cfg_mod.load_config()
        assert any("unknown config keys" in m for m in cm.output)
    finally:
        cfg_mod.set_runtime_config(old)


def test_skill_manage_deny_exemption_uses_real_hermes_home(monkeypatch, non_scratch_home):
    """Review #4: the skill_manage deny exemption must use the same Hermes home
    resolver as the rest of the plugin, not expanduser("~/.hermes").

    With HERMES_HOME pointed elsewhere, a deny entry naming that home must still be
    exempt for skill_manage (a Hermes-mediated, name-validated write), while a raw
    write_file to the same path stays blocked.

    Uses `non_scratch_home` so the fake Hermes home is not nested inside the real
    `~/.hermes` (which is on the default deny-list).
    """
    import sys
    import types
    from pathlib import Path
    import scope_fence.config as cfg_mod

    custom_home = Path(non_scratch_home) / "custom-hermes"
    custom_home.mkdir()
    # The plugin does `from hermes_constants import get_hermes_home` at call time,
    # so a fake module in sys.modules is picked up exactly like the real one.
    fake = types.ModuleType("hermes_constants")
    fake.get_hermes_home = lambda: str(custom_home)
    monkeypatch.setitem(sys.modules, "hermes_constants", fake)

    sid = "v8-n4"
    cfg_mod.set_runtime_config({"deny_paths": [str(custom_home), "~/.ssh"]})
    try:
        add_scope(sid, [str(custom_home)])
        invalidate_cache(sid)

        # skill_manage -> the custom Hermes home deny entry is exempt
        r = on_pre_tool_call(
            tool_name="skill_manage",
            args={"action": "create", "name": "x", "file_path": "SKILL.md"},
            session_id=sid,
        )
        assert r is None, f"skill_manage to the skills dir must be allowed, got: {r}"

        # write_file -> the deny entry must hold
        r2 = on_pre_tool_call(
            tool_name="write_file",
            args={"path": str(custom_home / "skills" / "x" / "SKILL.md")},
            session_id=sid,
        )
        assert r2 is not None and r2["action"] == "block", \
            "write_file to a denied path must block"
    finally:
        cfg_mod.set_runtime_config({})
