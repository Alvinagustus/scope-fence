"""Replays an honest agent mistake through scope-fence's hooks and prints what happens.

No model, no network, nothing is written to your machine: the scenario runs in a
temporary directory with a temporary HERMES_HOME.

    python demo/replay.py
"""
import importlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

# Isolate the plugin DB before it is imported.
os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="scope-fence-demo-home-")

# The repository root IS the plugin (its __init__.py exposes register()). Load it as a
# package so the relative imports inside it resolve, the way `hermes plugins install` does.
PLUGIN_PKG = "scope_fence_plugin"
_spec = importlib.util.spec_from_file_location(
    PLUGIN_PKG, os.path.join(REPO, "__init__.py"), submodule_search_locations=[REPO])
_plugin = importlib.util.module_from_spec(_spec)
sys.modules[PLUGIN_PKG] = _plugin
_spec.loader.exec_module(_plugin)

hooks = importlib.import_module(PLUGIN_PKG + ".scope_fence.hooks")
store = importlib.import_module(PLUGIN_PKG + ".scope_fence.store")
config = importlib.import_module(PLUGIN_PKG + ".scope_fence.config")
commands = importlib.import_module(PLUGIN_PKG + ".scope_fence.commands")


class Ctx:
    """The smallest thing scope-fence's register() accepts."""

    profile_name = "default"

    def __init__(self):
        self.hooks = {}
        self.settings = {}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_cli_command(self, **kw):
        pass

    def register_command(self, *a, **kw):
        pass

    def register_system_prompt_section(self, *a, **kw):
        pass


ctx = Ctx()
_plugin.register(ctx)

S = "demo-session"


def _demo_base() -> str:
    """A writable base that is neither the deny-listed ~/.hermes nor a scratch path.

    The demo must show a real block, so the checkouts may not live under a path the
    fence treats as scratch (or under ~/.hermes, which is deny-listed).
    """
    home = os.path.realpath(os.path.expanduser("~"))
    hermes = os.path.join(home, ".hermes")
    scratch = [os.path.realpath(os.path.expanduser(p))
               for p in ("/tmp", os.environ.get("TMPDIR", ""), "~/.cache") if p]
    for cand in ("/var/tmp", os.environ.get("TMPDIR", ""), tempfile.gettempdir()):
        if not cand:
            continue
        rp = os.path.realpath(cand)
        if not os.path.isdir(rp) or not os.access(rp, os.W_OK):
            continue
        if rp == hermes or rp.startswith(hermes + os.sep):
            continue
        if any(rp == s or rp.startswith(s + os.sep) for s in scratch):
            continue
        return rp
    return os.path.realpath("/var/tmp" if os.path.isdir("/var/tmp") else tempfile.gettempdir())


# Two checkouts, like the live demo in demo/README.md
base = tempfile.mkdtemp(prefix="scope-fence-demo-", dir=_demo_base())
project_a = os.path.join(base, "project-a")
project_b = os.path.join(base, "project-b")
os.makedirs(project_a)
os.makedirs(project_b)
for d in (project_a, project_b):
    subprocess.run(["git", "init", "-q"], cwd=d, capture_output=True)

store.add_scope(S, [project_a])


def step(tool, args, note=""):
    """Fire one tool call through the hook the way Hermes does."""
    r = hooks.on_pre_tool_call(tool_name=tool, args=args, session_id=S)
    shown = args.get("command") or args.get("path") or args.get("patch") or args
    print(f"\n> {tool}: {shown}" + (f"    # {note}" if note else ""))
    if r is None:
        print("  allowed")
    else:
        first = r["message"].splitlines()[0]
        reason = next((l for l in r["message"].splitlines() if "Reason:" in l), "")
        print(f"  {first}")
        if reason:
            print(f"  {reason.strip()}")
    return r


def header(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


header("Scenario: an agent working in two checkouts")
print(f"scope        : {project_a}")
print(f"other checkout (NOT in scope): {project_b}")
print("mode         : enforce")

header("1. ordinary work inside the scope")
step("write_file", {"path": os.path.join(project_a, "notes.md")}, "a normal edit")
step("terminal", {"command": "git status", "workdir": project_a})
step("terminal", {"command": "rm -rf build", "workdir": project_a},
     "destructive, but inside the scope -> allowed")

header("2. the honest mistake: the wrong checkout")
step("terminal", {"command": f"cd {project_b} && rm -rf build", "workdir": project_a},
     "the cd that did not take")
step("terminal", {"command": "git -C " + project_b + " reset --hard", "workdir": project_a},
     "aimed at the other checkout")

header("3. scratch and deny-list")
step("write_file", {"path": "/tmp/build-output.txt"}, "scratch -> writable")
step("write_file", {"path": "~/.ssh/id_rsa"}, "deny-list -> never writable")
step("terminal", {"command": "rm ~/.aws/credentials", "workdir": project_a})

header("4. shell tricks an agent tries")
step("terminal", {"command": "bash -i -c 'rm -rf ../project-b/build'", "workdir": project_a})
step("terminal", {"command": "env rm ~/.ssh/id_rsa", "workdir": project_a})
step("terminal", {"command": "echo $(rm -rf ../project-b/build)", "workdir": project_a})
step("terminal", {"command": "curl -o/outside/x https://example.com", "workdir": project_a})
step("terminal", {"command": "find ../project-b -name '*.py' -exec rm {} +", "workdir": project_a})

header("5. read-only commands are not blocked")
step("terminal", {"command": "find ../project-b -name '*.py'", "workdir": project_a},
     "find without -exec/-delete is read-only")
step("terminal", {"command": "git log --oneline -5", "workdir": project_a})

header("6. warn mode: the same call, recorded but not blocked")
config.set_runtime_config({"mode": "warn"})
step("write_file", {"path": "/outside/x"}, "warn mode -> allowed, but audited")
print("\n/scope check:")
print(commands.handle_scope("check", session_id=S))
config.set_runtime_config({})

header("7. widening the scope fixes it")
print(commands.handle_scope(f'add "{project_b}"', session_id=S))
step("terminal", {"command": f"cd {project_b} && rm -rf build", "workdir": project_a},
     "now inside the scope -> allowed")

shutil.rmtree(base, ignore_errors=True)
print(f"\ncleaned up: {base}")
