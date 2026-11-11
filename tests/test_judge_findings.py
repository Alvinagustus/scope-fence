"""Regression tests for the judge findings (B1, B2, B3, M1, M2, M3, M4)."""
import importlib.util
import os
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
from scope_fence.store import add_scope, invalidate_cache, record_block
from scope_fence.commands import handle_scope, _audit_tag

ROOT = os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), ".."))
PROJ = "/work/proj"


def _reset_breaker():
    with hooks_mod._BREAKER_LOCK:
        hooks_mod._BREAKER["errors"] = 0
        hooks_mod._BREAKER["open_until"] = 0.0
        hooks_mod._BREAKER["last_error"] = ""


def _open_breaker():
    with hooks_mod._BREAKER_LOCK:
        hooks_mod._BREAKER["errors"] = 3
        hooks_mod._BREAKER["open_until"] = time.time() + 60


# --------------------------------------------------------------------------- B1

def test_b1_demo_blocks_under_home(non_scratch_home):
    """The DEMO commands block when the checkouts live under $HOME (not a scratch path)."""
    a = os.path.join(str(non_scratch_home), "scope-fence-demo", "project-a")
    b = os.path.join(str(non_scratch_home), "scope-fence-demo", "project-b")
    os.makedirs(a)
    os.makedirs(b)
    invalidate_cache("demo")
    add_scope("demo", [a])
    invalidate_cache("demo")
    r = on_pre_tool_call(tool_name="terminal",
                         args={"command": f'cd "{b}" && rm -rf build', "workdir": a},
                         session_id="demo")
    assert r is not None and r["action"] == "block"
    assert "outside-scope" in r["message"]
    r = on_pre_tool_call(tool_name="terminal",
                         args={"command": f'git -C "{b}" reset --hard', "workdir": a},
                         session_id="demo")
    assert r is not None and r["action"] == "block"
    assert "outside-scope" in r["message"]


def test_b1_demo_tmp_paths_allowed():
    """The same commands against /tmp/... are ALLOWED — /tmp is a scratch path."""
    cfg_mod.set_runtime_config({"extra_write_paths": ["/tmp"]})
    try:
        invalidate_cache("demo2")
        add_scope("demo2", ["/tmp/demo/project-a"])
        invalidate_cache("demo2")
        r = on_pre_tool_call(tool_name="terminal",
                             args={"command": "cd /tmp/demo/project-b && rm -rf build",
                                   "workdir": "/tmp/demo/project-a"},
                             session_id="demo2")
        assert r is None, f"/tmp scratch should allow, got {r}"
        r = on_pre_tool_call(tool_name="terminal",
                             args={"command": "git -C /tmp/demo/project-b reset --hard",
                                   "workdir": "/tmp/demo/project-a"},
                             session_id="demo2")
        assert r is None, f"/tmp scratch should allow, got {r}"
    finally:
        cfg_mod.set_runtime_config({})


def test_b1_no_demo_doc():
    """Merged-submission convention: no docs/DEMO.md (airlock keeps demos in demo/)."""
    assert not os.path.exists(os.path.join(ROOT, "docs", "DEMO.md"))
    assert not os.path.isdir(os.path.join(ROOT, "docs"))


# --------------------------------------------------------------------------- B3

def test_b3_audit_row_classification():
    assert _audit_tag("would-block:outside-scope") == "WARN"
    assert _audit_tag("outside-scope") == "BLOCK"
    assert _audit_tag("deny-list") == "BLOCK"
    assert _audit_tag("unparseable") == "BLOCK"
    assert _audit_tag("auto-scope:/root") == "INFO"
    assert _audit_tag("breaker-open") == "ERR"
    assert _audit_tag("hook-error") == "ERR"


def test_b3_check_counts_and_labels():
    sid = "judge-b3"
    invalidate_cache(sid)
    add_scope(sid, [PROJ])
    invalidate_cache(sid)
    record_block(sid, "terminal", "/outside/x", "outside-scope")
    record_block(sid, "terminal", "/outside/y", "would-block:outside-scope")
    record_block(sid, "auto-scope", "/root/auto", "auto-scope")
    record_block(sid, "terminal", "boom", "breaker-open")
    record_block(sid, "terminal", "boom", "hook-error")
    out = handle_scope("check", session_id=sid)
    assert "1 would-block, 1 blocked, 3 info (last session)" in out, out
    assert "[WARN]" in out and "[BLOCK]" in out and "[INFO]" in out and "[ERR]" in out, out
    assert "Scope engaged automatically: /root/auto" in out, out
    # non-block rows are never counted as blocked
    assert "5 blocked" not in out


# --------------------------------------------------------------------------- M1

def test_m1_deny_list_enforced_while_breaker_open():
    _reset_breaker()
    _open_breaker()
    try:
        invalidate_cache("m1")
        add_scope("m1", [PROJ])
        invalidate_cache("m1")
        r = on_pre_tool_call(tool_name="terminal",
                             args={"command": "rm ~/.ssh/id_rsa", "workdir": PROJ},
                             session_id="m1")
        assert r is not None and r["action"] == "block", "deny-list must hold with the breaker open"
        assert "deny-list" in r["message"]
        # ordinary out-of-scope commands still pass (fail open)
        r = on_pre_tool_call(tool_name="terminal",
                             args={"command": "rm -rf /outside/x", "workdir": PROJ},
                             session_id="m1")
        assert r is None, f"breaker must fail open for scope violations, got {r}"
        # and for file tools too
        r = on_pre_tool_call(tool_name="write_file", args={"path": "~/.ssh/id_rsa"},
                             session_id="m1")
        assert r is not None and r["action"] == "block"
    finally:
        _reset_breaker()


# --------------------------------------------------------------------------- M2

def _load_make_corpus():
    path = os.path.join(os.path.dirname(__file__), "..", "tools", "make_corpus.py")
    spec = importlib.util.spec_from_file_location("sf_make_corpus", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_m2_redaction_patterns():
    mod = _load_make_corpus()
    home = "/home/alvin"
    lines = [
        "git status",                                             # benign, survives
        "curl https://ghp_ABCDEFGHIJKLMNOPQRSTUV@github.com/x",   # vendor token
        "export OPENAI_KEY=sk-abcdefghij1234567890",              # sk- token
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",     # JWT
        "curl https://user@github.com/x",                          # user@ (no password)
        "curl https://user:pass@github.com/x",                     # user:pass@
        "ls /home/someoneelse/project",                            # other home -> rewritten
        "ls /Users/someoneelse/project",                           # macOS home -> rewritten
    ]
    entries = mod.convert("\n".join(lines), home)
    cmds = [e["cmd"] for e in entries]
    assert "git status" in cmds, cmds
    assert not any("ghp_" in c for c in cmds), cmds
    assert not any("sk-abcdefghij" in c for c in cmds), cmds
    assert not any("eyJhbGciOiJIUzI1NiJ9" in c for c in cmds), cmds
    assert not any("user:pass@" in c for c in cmds), cmds
    assert not any("someoneelse" in c for c in cmds), cmds
    assert not any("/home/alvin" in c for c in cmds), "current home must be redacted"
    assert any("/home/user" in c for c in cmds), cmds


# --------------------------------------------------------------------------- M3

def test_m3_corpus_claims_are_honest():
    """The corpus is a development-repo artifact; the shipped README must not claim a
    real-world false-positive rate."""
    readme = open(os.path.join(ROOT, "README.md")).read()
    assert "false-positive rate" not in readme, \
        "the shipped README must not claim a measured FP rate"
    # the shipped tree carries no CHANGELOG (no version history before release)
    assert not os.path.exists(os.path.join(ROOT, "CHANGELOG.md"))


# --------------------------------------------------------------------------- M4

def test_m4_fixture_guard_fails_loudly():
    from tests.conftest import assert_not_under_scratch
    try:
        assert_not_under_scratch("/tmp/x", ["/tmp"], "demo path")
    except AssertionError as e:
        assert "scratch root" in str(e)
    else:
        raise AssertionError("expected assert_not_under_scratch to fail for /tmp")
    # a non-scratch path passes
    assert_not_under_scratch("/opt/x", ["/tmp"], "demo path")


def test_m4_demo_paths_are_not_scratch(non_scratch_home):
    """The demo HOME fixture must not resolve under a scratch root."""
    from tests.conftest import is_scratch
    assert not is_scratch(str(non_scratch_home), ["/tmp", "~/.cache"]), \
        "the demo fixture must live outside the scratch paths"
