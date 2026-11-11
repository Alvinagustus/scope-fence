"""Runtime test: load scope-fence through the REAL Hermes PluginManager and fire hooks.

Not a unit test — this exercises the actual discovery -> manifest -> import -> register
-> hook-dispatch path, exactly as Hermes does at runtime.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1])

# A Hermes source checkout makes hermes_cli importable; otherwise fall back to an
# installed Hermes (site-packages) so this runs on a plain install too.
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

# HERMES_HOME must be set before hermes_cli is imported.
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

HOME = tempfile.mkdtemp(prefix="sf-runtime-home-", dir=BASE)
PLUGINS = os.path.join(HOME, "plugins")
os.makedirs(PLUGINS, exist_ok=True)
os.environ["HERMES_HOME"] = HOME
os.environ["HERMES_ENABLE_PROJECT_PLUGINS"] = "0"

sys.path.insert(0, HERMES_SRC)
shutil.copytree(SRC, os.path.join(PLUGINS, "scope-fence"))

from hermes_cli.plugins import PluginManager  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    ok = got == want
    PASS += ok
    FAIL += (not ok)
    print(f"  [{'OK ' if ok else 'FAIL'}] {label:<56} got={got} want={want}")


def main():
    # Run from a directory that is not a git repo: otherwise auto-scope engages to the
    # surrounding checkout and the "fence inactive" assertions no longer hold.
    os.chdir(BASE)
    print(f"HERMES_HOME = {HOME}")
    manager = PluginManager(scope_key=HOME)
    manifests = manager._scan_directory(__import__("pathlib").Path(PLUGINS), source="user")
    print(f"discovered: {[m.name for m in manifests]}")
    for m in manifests:
        manager._load_plugin(m)
    loaded = [k for k, v in manager._plugins.items() if not v.error]
    print(f"loaded: {loaded}  errors: {[v.error for v in manager._plugins.values() if v.error]}")

    # registered hooks / command
    hooks = {k: len(v) for k, v in manager._hooks.items() if v}
    print(f"registered hooks: {hooks}")
    print(f"registered commands: {list(manager._plugin_commands)}")

    sid = "runtime-test"

    def pre(tool, args):
        res = manager.invoke_hook("pre_tool_call", tool_name=tool, args=args,
                                  session_id=sid, conversation_id="", turn_id="t1",
                                  tool_call_id="tc1")
        for r in res:
            if isinstance(r, dict) and r.get("action") == "block":
                return "block"
        return "allow"

    print("\n--- fence inactive (no scope) ---")
    check("write /outside/x", pre("write_file", {"path": "/outside/x"}), "allow")
    check("rm ~/.ssh/id_rsa (deny, no scope)", pre("terminal", {"command": "rm ~/.ssh/id_rsa", "workdir": "/work/proj"}), "block")
    check("echo hi > ~/.ssh/authorized_keys", pre("terminal", {"command": "echo hi > ~/.ssh/authorized_keys", "workdir": "/work/proj"}), "block")

    print("\n--- add scope /work/proj via the real command handler ---")
    cmd = manager._plugin_commands.get("scope")
    print(f"  command entry: {cmd}")
    handler = cmd["handler"] if cmd else None
    if handler:
        out = handler("add /work/proj", session_id=sid)
        print(f"  /scope add -> {out.splitlines()[0] if out else '(empty)'}")
        out2 = handler("list", session_id=sid)
        print(f"  /scope list -> {'Active: yes' in out2}")

    print("\n--- scope active ---")
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

    print("\n--- /scope check / doctor ---")
    if handler:
        chk = handler("check", session_id=sid)
        print(f"  check has mode: {'Mode:' in chk}, scratch: {'Scratch paths' in chk}")
        doc = handler("doctor", session_id=sid)
        print(f"  doctor lines: {len(doc.splitlines())}, all tagged: {all(l[:4].strip() in ('OK','WARN','FAIL') for l in doc.splitlines()[1:])}")

    print("\n--- warn mode via the real config file ---")
    cfg_path = os.path.join(HOME, "config.yaml")
    with open(cfg_path, "w") as f:
        f.write(
            "plugins:\n"
            "  entries:\n"
            "    scope-fence:\n"
            "      settings:\n"
            "        mode: warn\n"
            "        extra_write_paths: [/tmp]\n"
        )
    manager2 = PluginManager(scope_key=HOME)
    manager2._scan_directory(__import__("pathlib").Path(PLUGINS), source="user")
    for m in list(manager2._plugins):
        pass
    for m in manager2._scan_directory(__import__("pathlib").Path(PLUGINS), source="user"):
        manager2._load_plugin(m)

    def pre2(tool, args):
        res = manager2.invoke_hook("pre_tool_call", tool_name=tool, args=args,
                                   session_id=sid, conversation_id="", turn_id="t1",
                                   tool_call_id="tc1")
        for r in res:
            if isinstance(r, dict) and r.get("action") == "block":
                return "block"
        return "allow"

    out = manager2._plugin_commands["scope"]["handler"]("add /work/proj", session_id=sid)
    print(f"  /scope add -> {out.splitlines()[0]}")
    check("warn: write outside scope ALLOWS", pre2("write_file", {"path": "/outside/x"}), "allow")
    check("warn: deny-list still BLOCKS", pre2("terminal", {"command": "rm ~/.ssh/id_rsa", "workdir": "/work/proj"}), "block")
    chk = manager2._plugin_commands["scope"]["handler"]("check", session_id=sid)
    print(f"  check shows [WARN]: {'[WARN]' in chk}")
    print(f"  check summary: {[l for l in chk.splitlines() if 'Summary' in l]}")

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    shutil.rmtree(HOME, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
