"""Regression tests for the deny-list leak, python floor, system prompt, auto-scope
cache, scratch paths, warn mode, circuit breaker and /scope doctor messages."""
import os
import subprocess
import sys
import tempfile
import time

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
    for t in [
        "scopes (session_id TEXT NOT NULL, path TEXT NOT NULL, added_at REAL NOT NULL, PRIMARY KEY (session_id, path))",
        "cwd_state (session_id TEXT PRIMARY KEY, cwd TEXT, updated_at REAL NOT NULL)",
        "audit (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 1, command TEXT)",
        "session_alias (session_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL)",
    ]:
        conn.execute("CREATE TABLE IF NOT EXISTS " + t)
    conn.commit()
    _DB_CONN = conn
    return conn


store_mod._get_db = lambda hermes_home=None: _init_test_db()

import scope_fence.config as cfg_mod
import scope_fence.hooks as hooks_mod
from scope_fence.hooks import on_pre_tool_call
from scope_fence.store import add_scope, invalidate_cache, get_audit
from scope_fence.commands import handle_scope

ROOT = os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), ".."))
PROJ = "/work/proj"
HOME = os.path.realpath(os.path.expanduser("~"))


def _reset_breaker():
    with hooks_mod._BREAKER_LOCK:
        hooks_mod._BREAKER["errors"] = 0
        hooks_mod._BREAKER["open_until"] = 0.0
        hooks_mod._BREAKER["last_error"] = ""


def _fresh(sid, roots=None, cwd=None):
    invalidate_cache(sid)
    if roots:
        add_scope(sid, roots)
    if cwd:
        from scope_fence.store import record_cwd
        record_cwd(sid, cwd)
    invalidate_cache(sid)


def _term(cmd, cfg=None, roots=None, cwd=PROJ):
    cfg_mod.set_runtime_config(cfg or {})
    _fresh("v", roots if roots is not None else [PROJ], cwd)
    r = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": cwd}, session_id="v")
    return "allow" if r is None else "block:" + ("deny" if "deny-list" in r["message"] else "scope")


def _tool(tn, args, cfg=None, roots=None):
    cfg_mod.set_runtime_config(cfg or {})
    _fresh("v", roots if roots is not None else [PROJ])
    r = on_pre_tool_call(tool_name=tn, args=args, session_id="v")
    return "allow" if r is None else "block:" + ("deny" if "deny-list" in r["message"] else "scope")


# --------------------------------------------------------------------- deny-list leak

def test_no_scope_deny_list_enforced():
    """With NO scope, deny-listed write targets must still block."""
    for cmd in ["env rm ~/.ssh/id_rsa",
                "echo hi > ~/.ssh/authorized_keys",
                "printf x >> ~/.bashrc"]:
        assert _term(cmd, roots=None) == "block:deny", f"no-scope should block: {cmd}"
        assert _term(cmd, roots=[HOME]) == "block:deny", f"scope=HOME should block: {cmd}"
    # a mere mention is still allowed
    assert _term("echo ~/.ssh", roots=None) == "allow"
    assert _term("printf 'a' >> /tmp/x", roots=None) == "allow"


# --------------------------------------------------------------------- python floor

def test_requires_python_39():
    """No pyproject.toml ships (directory-installed), so there is no python floor to declare."""
    assert not os.path.exists(os.path.join(ROOT, "pyproject.toml"))


# --------------------------------------------------------------------- system prompt

def test_system_prompt_text():
    src = open(os.path.join(ROOT, "__init__.py")).read()
    assert "No scope is declared yet; it will auto-scope" in src
    assert "Writes are not restricted" not in src
    assert "max_chars=1000" in src


# --------------------------------------------------------------------- auto-scope cache

def test_auto_scope_cache_expires_and_is_per_session():
    d = tempfile.mkdtemp()
    try:
        sid = "asc-2d"
        assert hooks_mod._try_git_root(d, sid) is None
        subprocess.run(["git", "init", "-q"], cwd=d, capture_output=True)
        assert hooks_mod._try_git_root(d, sid) is None, "failure must be cached"
        # expire the entry
        with hooks_mod._AUTO_SCOPE_LOCK:
            for k in list(hooks_mod._AUTO_SCOPE_FAILED):
                if k[0] == sid:
                    hooks_mod._AUTO_SCOPE_FAILED[k] = 0.0
        assert hooks_mod._try_git_root(d, sid) is not None, "expired entry must be retried"
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def test_reset_warnings_only_drops_own_session():
    hooks_mod._AUTO_SCOPE_FAILED[("A", "/x")] = time.time() + 60
    hooks_mod._AUTO_SCOPE_FAILED[("B", "/y")] = time.time() + 60
    try:
        hooks_mod._reset_warnings("A")
        assert ("A", "/x") not in hooks_mod._AUTO_SCOPE_FAILED
        assert ("B", "/y") in hooks_mod._AUTO_SCOPE_FAILED, "other sessions must survive"
    finally:
        hooks_mod._AUTO_SCOPE_FAILED.clear()


# --------------------------------------------------------------------- scratch paths

def test_scratch_paths_writable():
    assert _term("echo x > /tmp/out.txt") == "allow"
    assert _term("touch /tmp/a") == "allow"
    assert _tool("write_file", {"path": "/tmp/a.txt"}) == "allow"
    assert _term("pip install -r requirements.txt") == "allow"
    # outside scratch and scope still blocks
    assert _term("rm -rf /outside/x") == "block:scope"
    # deny wins over scratch
    assert _term("echo x > ~/.ssh/id_rsa") == "block:deny"
    assert _term("rm -rf ~/.cache/../.ssh/id_rsa") == "block:deny"


def test_extra_write_paths_rejects_root():
    cfg_mod.set_runtime_config({"extra_write_paths": ["/"]})
    try:
        roots = cfg_mod.extra_write_roots()
        assert all(str(r) != "/" for r in roots), "filesystem root must be rejected"
    finally:
        cfg_mod.set_runtime_config({})


def test_extra_write_paths_additive_over_defaults():
    """Review #3: extra_write_paths extends the defaults, like deny_paths does."""
    import os
    cfg_mod.set_runtime_config({"extra_write_paths": ["/var/tmp/custom-scratch"]})
    try:
        roots = [str(r) for r in cfg_mod.extra_write_roots()]
        # the defaults stay
        assert any(r == os.path.realpath("/tmp") for r in roots), roots
        assert any(r == os.path.realpath(os.path.expanduser("~/.cache")) for r in roots), roots
        # the user entry is added
        assert any(r == os.path.realpath("/var/tmp/custom-scratch") for r in roots), roots
    finally:
        cfg_mod.set_runtime_config({})


def test_extra_write_paths_replace_flag():
    """Review #3: replace_default_extra_write_paths drops the defaults."""
    import os
    cfg_mod.set_runtime_config({
        "extra_write_paths": ["/var/tmp/custom-scratch"],
        "replace_default_extra_write_paths": True,
    })
    try:
        roots = [str(r) for r in cfg_mod.extra_write_roots()]
        assert roots == [os.path.realpath("/var/tmp/custom-scratch")], roots
    finally:
        cfg_mod.set_runtime_config({})


def test_extra_write_paths_empty_list_keeps_defaults():
    """An empty list adds nothing; the defaults still apply."""
    cfg_mod.set_runtime_config({"extra_write_paths": []})
    try:
        roots = [str(r) for r in cfg_mod.extra_write_roots()]
        assert any(r == os.path.realpath("/tmp") for r in roots), roots
    finally:
        cfg_mod.set_runtime_config({})


# --------------------------------------------------------------------- warn mode

def test_warn_mode():
    sid = "warn-mode"
    _fresh(sid, [PROJ], PROJ)
    cfg_mod.set_runtime_config({"mode": "warn"})
    try:
        r = on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf /outside/x", "workdir": PROJ},
                             session_id=sid)
        assert r is None, "warn mode must not block scope violations"
        audit = get_audit(sid)
        assert any(a["reason"] == "would-block:outside-scope" for a in audit), \
            f"expected would-block audit row, got {audit}"
        # deny-list still enforced
        r = on_pre_tool_call(tool_name="terminal", args={"command": "rm ~/.ssh/id_rsa", "workdir": PROJ},
                             session_id=sid)
        assert r is not None and r["action"] == "block", "deny-list must block in warn mode"
    finally:
        cfg_mod.set_runtime_config({})
    # enforce blocks again
    assert _term("rm -rf /outside/x") == "block:scope"


def test_invalid_mode_falls_back():
    cfg = cfg_mod.validate_config({"mode": "nope"})
    assert cfg["mode"] == "enforce"


# --------------------------------------------------------------------- circuit breaker

def test_circuit_breaker():
    _reset_breaker()
    _fresh("cb", [PROJ], PROJ)
    orig = hooks_mod._pre_tool_call_impl

    def boom(*a, **k):
        raise RuntimeError("boom")

    hooks_mod._pre_tool_call_impl = boom
    try:
        for i in (1, 2):
            r = hooks_mod.on_pre_tool_call(tool_name="write_file", args={"path": "/outside/x"},
                                           session_id="cb")
            assert r is not None, f"error {i} must fail closed"
        r3 = hooks_mod.on_pre_tool_call(tool_name="write_file", args={"path": "/outside/x"},
                                        session_id="cb")
        assert r3 is None, "3rd consecutive error must open the breaker (fail open)"
        r4 = hooks_mod.on_pre_tool_call(tool_name="write_file", args={"path": "/outside/x"},
                                        session_id="cb")
        assert r4 is None, "breaker must stay open"
        # expiry
        with hooks_mod._BREAKER_LOCK:
            hooks_mod._BREAKER["open_until"] = 0.0
        # a success resets the counter
        hooks_mod._pre_tool_call_impl = orig
        r5 = hooks_mod.on_pre_tool_call(tool_name="write_file", args={"path": "/outside/x"},
                                        session_id="cb")
        assert r5 is not None, "after expiry the fence evaluates normally"
        assert hooks_mod._BREAKER["errors"] == 0, "success must reset the counter"
    finally:
        hooks_mod._pre_tool_call_impl = orig
        _reset_breaker()


# --------------------------------------------------------------------- /scope doctor

def test_doctor_output_shape():
    out = handle_scope("doctor", session_id="doc")
    assert isinstance(out, str) and out
    assert "breaker" in out
    assert "scope roots" in out
    assert "hook counters" in out
    # no session id -> WARN
    out2 = handle_scope("doctor", session_id="")
    assert "WARN" in out2


def test_doctor_never_raises():
    # degraded DB
    orig = store_mod._get_db
    store_mod._get_db = lambda hermes_home=None: (_ for _ in ()).throw(RuntimeError("no db"))
    try:
        out = handle_scope("doctor", session_id="doc-degraded")
        assert "FAIL" in out
    finally:
        store_mod._get_db = orig


# --------------------------------------------------------------------- /scope doctor.5

def test_recovery_line_and_length():
    long_cmd = "rm -rf /outside/" + ("x" * 500)
    cfg_mod.set_runtime_config({})
    _fresh("v", [PROJ], PROJ)
    r = on_pre_tool_call(tool_name="terminal", args={"command": long_cmd, "workdir": PROJ}, session_id="v")
    assert r is not None
    assert "Do not retry this command" in r["message"]
    assert len(r["message"]) <= 600, f"message too long: {len(r['message'])}"
