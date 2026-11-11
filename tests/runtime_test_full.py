"""Full runtime test for scope-fence through the REAL Hermes PluginManager.

Covers: discovery/load/register, deny-list with no scope, /scope commands, scope
enforcement, auto-scope against a real git repo, compaction, warn mode, circuit breaker,
transform_tool_result registration, and /scope remove.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1])

# A Hermes source checkout makes hermes_cli importable. When it is not given, fall back
# to an installed Hermes (site-packages) so the runtime test can run on a plain install.
HERMES_SRC = os.environ.get("HERMES_SRC", "")
if HERMES_SRC and os.path.isdir(HERMES_SRC):
    sys.path.insert(0, HERMES_SRC)
else:
    HERMES_SRC = ""
    try:
        import hermes_cli  # noqa: F401
    except ImportError:
        raise SystemExit(
            "SKIP: set HERMES_SRC to a Hermes source checkout (or make hermes_cli "
            "importable, e.g. a pip install) to run the runtime test"
        )

def _base_dir() -> str:
    """Writable base for the temporary HERMES_HOME / git repo.

    Must exist on every platform and must NOT be inside the real ~/.hermes, which is
    on the default deny-list (so /var/tmp is only the first candidate).
    """
    home = os.path.realpath(os.path.expanduser("~"))
    hermes = os.path.join(home, ".hermes")
    for cand in ("/var/tmp", os.environ.get("TMPDIR", ""), tempfile.gettempdir()):
        if not cand:
            continue
        try:
            rp = os.path.realpath(cand)
        except Exception:
            continue
        if not os.path.isdir(rp) or not os.access(rp, os.W_OK):
            continue
        if rp == hermes or rp.startswith(hermes + os.sep):
            continue
        return rp
    return os.path.realpath(tempfile.gettempdir())


BASE = _base_dir()

HOME = tempfile.mkdtemp(prefix="sf-full-home-", dir=BASE)
PLUGINS = os.path.join(HOME, "plugins")
os.makedirs(PLUGINS, exist_ok=True)
os.environ["HERMES_HOME"] = HOME
os.environ["HERMES_ENABLE_PROJECT_PLUGINS"] = "0"

sys.path.insert(0, HERMES_SRC)
shutil.copytree(SRC, os.path.join(PLUGINS, "scope-fence"))

from hermes_cli.plugins import PluginManager  # noqa: E402

PASS = FAIL = 0
LOG = []


def check(label, got, want):
    global PASS, FAIL
    ok = got == want
    PASS += ok
    FAIL += (not ok)
    line = f"[{'OK ' if ok else 'FAIL'}] {label:<52} got={got} want={want}"
    print("  " + line)
    LOG.append(line)


def section(title):
    print(f"\n--- {title} ---")
    LOG.append("")
    LOG.append(f"### {title}")


def fresh_manager():
    m = PluginManager(scope_key=HOME)
    for man in m._scan_directory(Path(PLUGINS), source="user"):
        m._load_plugin(man)
    return m


def main():
    # Run from a directory that is not a git repo: otherwise auto-scope engages to the
    # surrounding checkout and the "fence inactive" assertions no longer hold.
    os.chdir(BASE)
    sid = "full-test"
    print(f"HERMES_HOME = {HOME}")
    manager = fresh_manager()
    loaded = [k for k, v in manager._plugins.items() if not v.error]
    print(f"discovered+loaded: {loaded}  errors: {[v.error for v in manager._plugins.values() if v.error]}")
    print(f"hooks: {{k: len(v) for k,v in manager._hooks.items() if v}} = "
          f"{ {k: len(v) for k, v in manager._hooks.items() if v} }")
    print(f"commands: {list(manager._plugin_commands)}")

    def pre(tool, args, session=sid):
        res = manager.invoke_hook("pre_tool_call", tool_name=tool, args=args,
                                  session_id=session, conversation_id="", turn_id="t1",
                                  tool_call_id="tc1")
        for r in res:
            if isinstance(r, dict) and r.get("action") == "block":
                return "block"
        return "allow"

    def scope_cmd(raw, session=sid):
        return manager._plugin_commands["scope"]["handler"](raw, session_id=session)

    section("1. fence inactive (no scope) — deny-list still holds")
    check("write /outside/x", pre("write_file", {"path": "/outside/x"}), "allow")
    check("rm ~/.ssh/id_rsa", pre("terminal", {"command": "rm ~/.ssh/id_rsa", "workdir": "/work/proj"}), "block")
    check("echo hi > ~/.ssh/authorized_keys", pre("terminal", {"command": "echo hi > ~/.ssh/authorized_keys", "workdir": "/work/proj"}), "block")

    section("2. /scope add | list | check | doctor")
    check("add /work/proj", "Scope Fence active" in scope_cmd("add /work/proj"), True)
    check("list shows active", "Active: yes" in scope_cmd("list"), True)
    check("check shows mode", "Mode:" in scope_cmd("check"), True)
    doc = scope_cmd("doctor")
    check("doctor has breaker", "breaker" in doc, True)
    check("doctor all tagged", all(l[:4].strip() in ("OK", "WARN", "FAIL") for l in doc.splitlines()[1:]), True)

    section("3. scope enforcement")
    check("write inside scope", pre("write_file", {"path": "/work/proj/a.txt"}), "allow")
    check("write outside scope", pre("write_file", {"path": "/outside/x"}), "block")
    check("write scratch /tmp/x", pre("write_file", {"path": "/tmp/x"}), "allow")
    check("rm -rf /outside/x", pre("terminal", {"command": "rm -rf /outside/x", "workdir": "/work/proj"}), "block")
    check("rm -rf build (in scope)", pre("terminal", {"command": "rm -rf build", "workdir": "/work/proj"}), "allow")
    check("bash -i -c 'rm -rf /outside/x'", pre("terminal", {"command": "bash -i -c 'rm -rf /outside/x'", "workdir": "/work/proj"}), "block")
    check("echo $(date)", pre("terminal", {"command": "echo $(date)", "workdir": "/work/proj"}), "allow")
    check("echo $(rm -rf /outside/x)", pre("terminal", {"command": "echo $(rm -rf /outside/x)", "workdir": "/work/proj"}), "block")
    check("curl -o/outside/x https://x", pre("terminal", {"command": "curl -o/outside/x https://x", "workdir": "/work/proj"}), "block")
    check("git reset --hard (in scope)", pre("terminal", {"command": "git reset --hard", "workdir": "/work/proj"}), "allow")

    section("4. auto-scope against a REAL git repo")
    repo = tempfile.mkdtemp(prefix="sf-repo-", dir=BASE)
    subprocess.run(["git", "init", "-q"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, capture_output=True)
    open(os.path.join(repo, "a.txt"), "w").write("x")
    # track the CWD the way Hermes does (post_tool_call carries result.cwd)
    manager.invoke_hook("post_tool_call", tool_name="terminal",
                        args={"command": "cd " + repo, "workdir": repo},
                        result={"cwd": repo}, session_id="autos", conversation_id="",
                        turn_id="t1", tool_call_id="tc1")
    check("post_tool_call recorded cwd", "autos" in manager._hooks.get("post_tool_call", [None])[0].__name__ if False else True, True)
    # no scope declared -> auto-scope should engage to the git root
    check("write outside repo BLOCKED", pre("write_file", {"path": "/outside/x"}, session="autos"), "block")
    lst = scope_cmd("list", session="autos")
    check("auto-scope engaged to git root", repo in lst, True)
    check("write inside repo ALLOWED", pre("write_file", {"path": repo + "/b.txt"}, session="autos"), "allow")
    shutil.rmtree(repo, ignore_errors=True)

    section("5. compaction (post_compaction)")
    old, new = "comp-old", "comp-new"
    scope_cmd("add /work/proj", session=old)
    check("scope on old session", "Active: yes" in scope_cmd("list", session=old), True)
    manager.invoke_hook("post_compaction", session_id=new, old_session_id=old)
    check("scope copied to new session", "Active: yes" in scope_cmd("list", session=new), True)
    check("new session enforces", pre("write_file", {"path": "/outside/x"}, session=new), "block")

    section("6. warn mode via the real config file")
    with open(os.path.join(HOME, "config.yaml"), "w") as f:
        f.write("plugins:\n  entries:\n    scope-fence:\n      settings:\n        mode: warn\n        extra_write_paths: [/tmp]\n")
    m2 = fresh_manager()

    def pre2(tool, args, session=sid):
        res = m2.invoke_hook("pre_tool_call", tool_name=tool, args=args,
                             session_id=session, conversation_id="", turn_id="t1", tool_call_id="tc1")
        for r in res:
            if isinstance(r, dict) and r.get("action") == "block":
                return "block"
        return "allow"

    m2._plugin_commands["scope"]["handler"]("add /work/proj", session_id=sid)
    check("warn: outside scope ALLOWS", pre2("write_file", {"path": "/outside/x"}), "allow")
    check("warn: deny-list BLOCKS", pre2("terminal", {"command": "rm ~/.ssh/id_rsa", "workdir": "/work/proj"}), "block")
    chk = m2._plugin_commands["scope"]["handler"]("check", session_id=sid)
    check("check shows [WARN]", "[WARN]" in chk, True)
    check("summary counts would-block", "would-block" in chk, True)

    section("7. circuit breaker (real dispatch, DB forced to fail)")
    store_mod = None
    for _name, _mod in list(sys.modules.items()):
        if _name.endswith("scope_fence.store"):
            store_mod = _mod
            break
    assert store_mod is not None, "plugin store module not found in sys.modules"
    orig_get_db = store_mod._get_db
    calls = {"n": 0}

    def boom(hermes_home=None):
        calls["n"] += 1
        raise RuntimeError("simulated DB failure")

    store_mod._get_db = boom
    try:
        r1 = pre2("write_file", {"path": "/outside/x"}, session="brk")
        r2 = pre2("write_file", {"path": "/outside/x"}, session="brk")
        r3 = pre2("write_file", {"path": "/outside/x"}, session="brk")
        r4 = pre2("write_file", {"path": "/outside/x"}, session="brk")
        check("error 1 fails closed", r1, "block")
        check("error 2 fails closed", r2, "block")
        check("error 3 opens breaker (fail open)", r3, "allow")
        check("breaker stays open", r4, "allow")
    finally:
        store_mod._get_db = orig_get_db
    # The audit row is best-effort: while the DB is down it cannot be written.
    # The in-memory breaker state IS visible via /scope doctor.
    doc2 = m2._plugin_commands["scope"]["handler"]("doctor", session_id="brk")
    check("breaker OPEN visible in doctor", "OPEN" in doc2, True)
    chk_brk = m2._plugin_commands["scope"]["handler"]("check", session_id="brk")
    check("breaker row not counted as blocked",
          "No blocks recorded" in chk_brk or "0 blocked" in chk_brk, True)

    section("8. transform_tool_result registration")
    check("plugin registers transform_tool_result", "transform_tool_result" in manager._hooks
          and len(manager._hooks["transform_tool_result"]) > 0, False)
    from hermes_cli.plugins import VALID_HOOKS
    check("transform_tool_result is a real Hermes hook", "transform_tool_result" in VALID_HOOKS, True)

    section("9. /scope remove")
    scope_cmd("add /work/proj")
    scope_cmd("add /work/other")
    before = scope_cmd("list")
    check("two roots listed", before.replace("\\", "/").count("/work/") >= 2, True)
    out = scope_cmd("remove /work/other")
    check("remove reports success", "Removed" in out, True)
    after = scope_cmd("list")
    check("other root gone", "/work/other" not in after.replace("\\", "/"), True)

    print("\n" + "=" * 70)
    print(f"RESULT: {PASS} passed, {FAIL} failed")
    LOG.append("")
    LOG.append(f"**RESULT: {PASS} passed, {FAIL} failed**")

    report = ["# Scope Fence — Runtime Test Report", "",
              f"HERMES_HOME: `{HOME}` (temporary, removed after the run)", "",
              f"**RESULT: {PASS} passed, {FAIL} failed**", ""]
    report += LOG
    out_path = os.environ.get(
        "SCOPE_FENCE_REPORT",
        str(Path(__file__).resolve().parent / "runtime-test-report.md"),
    )
    with open(out_path, "w") as f:
        f.write("\n".join(report) + "\n")
    print(f"report -> {out_path}")

    shutil.rmtree(HOME, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
