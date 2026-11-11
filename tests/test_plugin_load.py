"""Tests for loading the plugin under the hermes_plugins.* namespace."""
import importlib.util
import os
import sys
import types

import pytest
from conftest import SCRATCH

PLUGIN_DIR = os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), ".."))


def _load_as_hermes_plugins():
    """Load the plugin as hermes_plugins.scope_fence, mirroring the real loader."""
    if "hermes_plugins" not in sys.modules:
        pkg = types.ModuleType("hermes_plugins")
        pkg.__path__ = []
        sys.modules["hermes_plugins"] = pkg
    if "hermes_plugins.scope_fence" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "hermes_plugins.scope_fence",
            os.path.join(PLUGIN_DIR, "__init__.py"),
            submodule_search_locations=[PLUGIN_DIR],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["hermes_plugins.scope_fence"] = mod
        spec.loader.exec_module(mod)
        setattr(sys.modules["hermes_plugins"], "scope_fence", mod)
    return sys.modules["hermes_plugins.scope_fence"]


class FakeCtx:
    def __init__(self, config):
        self._config = config
        self.hooks = []
        self.commands = []
        self.prompt_sections = []

    def get_config(self, key, default=None):
        return self._config.get(key, default)

    def register_hook(self, name, fn):
        self.hooks.append((name, fn))

    def register_command(self, name, fn, description="", args_hint=""):
        self.commands.append((name, fn))

    def register_system_prompt_section(self, name, fn):
        self.prompt_sections.append((name, fn))


def test_loads_under_hermes_plugins_namespace():
    mod = _load_as_hermes_plugins()
    assert mod.__name__ == "hermes_plugins.scope_fence"
    assert hasattr(mod, "register")


def test_config_read_via_ctx_get_config():
    mod = _load_as_hermes_plugins()
    ctx = FakeCtx({"strict_mode": True, "deny_paths": ["/tmp/deny"]})
    mod.register(ctx)
    # Read config from the plugin's own namespace, not the top-level alias
    import hermes_plugins.scope_fence.scope_fence.config as cfg_mod
    cfg = cfg_mod.load_config()
    assert cfg["strict_mode"] is True
    # D5: user deny_paths are additive over the defaults by default
    assert "/tmp/deny" in cfg["deny_paths"]
    assert "~/.ssh" in cfg["deny_paths"]


def test_system_prompt_shows_active_scope():
    mod = _load_as_hermes_plugins()
    ctx = FakeCtx({})
    mod.register(ctx)
    assert ctx.prompt_sections, "prompt section should be registered"
    name, fn = ctx.prompt_sections[0]
    import tempfile
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        from hermes_plugins.scope_fence.scope_fence.store import add_scope
        sid = "prompt-test"
        add_scope(sid, [d])
        text = fn({"session_id": sid})
        assert "ACTIVE" in text
        assert d in text


def test_hooks_registered():
    mod = _load_as_hermes_plugins()
    ctx = FakeCtx({})
    mod.register(ctx)
    names = [n for n, _ in ctx.hooks]
    assert "pre_tool_call" in names
    assert "post_tool_call" in names
    assert "on_session_finalize" in names
