"""Shared pytest fixtures for the scope-fence test suite.

The plugin lives in this folder's parent (the repository root), so the loader
adds it to sys.path the way `hermes plugins install` would.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

# The plugin tree is the repository root, one level above tests/.
PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from scope_fence import config as cfg_mod
from scope_fence.paths import is_inside, resolve

# A writable scratch directory on every platform. Tests must not hardcode "/tmp":
# on Windows that path does not exist and tempfile.TemporaryDirectory would raise.
# Prefer a directory the plugin already treats as scratch (/tmp, $TMPDIR, ~/.cache).
def _scratch_dir() -> str:
    candidates = ["/tmp", os.environ.get("TMPDIR", ""), "~/.cache", tempfile.gettempdir()]
    for cand in candidates:
        if not cand:
            continue
        try:
            rp = os.path.realpath(os.path.expanduser(cand))
        except Exception:
            continue
        if os.path.isdir(rp) and os.access(rp, os.W_OK):
            return rp
    return os.path.realpath(tempfile.gettempdir())


SCRATCH = _scratch_dir()


def _ambient_scratch_roots():
    roots = ["/tmp", os.environ.get("TMPDIR", ""), "~/.cache"]
    return [resolve(r) for r in roots if r]


def _non_scratch_base():
    """A writable directory that is NOT under an ambient scratch root."""
    scratch = _ambient_scratch_roots()
    candidates = ["/var/tmp", "/opt", "/usr/local/var",
                  os.path.realpath(os.path.expanduser("~"))]
    for cand in candidates:
        try:
            if not os.path.isdir(cand) or not os.access(cand, os.W_OK):
                continue
            rp = resolve(cand)
            if any(is_inside(rp, [s]) for s in scratch):
                continue
            return cand
        except Exception:
            continue
    raise RuntimeError(
        "no writable non-scratch base found for the test fixture "
        f"(scratch roots: {[str(s) for s in scratch]})"
    )


@pytest.fixture
def non_scratch_home(tmp_path_factory, monkeypatch):
    """A temporary HOME that is NOT under /tmp, $TMPDIR or ~/.cache.

    Tests that reproduce user-facing behaviour (the demo, docs examples) use this so
    they do not depend on the ambient cwd or HOME being outside the scratch paths.
    Scratch paths are cleared too, so the fence treats the fixture like any other
    directory. Yields the fake home directory.
    """
    base = _non_scratch_base()
    home = tempfile.mkdtemp(prefix="fakehome-", dir=base)
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("USERPROFILE", home)  # Windows
    cfg_mod.set_runtime_config({"extra_write_paths": []})
    try:
        yield home
    finally:
        cfg_mod.set_runtime_config({})
        try:
            os.rmdir(home)
        except OSError:
            pass


def assert_not_under_scratch(path, scratch_roots, label="fixture path"):
    """Fail loudly if `path` resolves under one of `scratch_roots`."""
    rp = resolve(str(path))
    for root in scratch_roots:
        if is_inside(rp, [resolve(str(root))]):
            raise AssertionError(
                f"{label} {rp} resolves under scratch root {root}; "
                "the test would not exercise the intended behaviour"
            )


def is_scratch(path, extra_write_paths):
    """True when `path` resolves under one of the given scratch roots."""
    rp = resolve(str(path))
    return any(is_inside(rp, [resolve(str(r))]) for r in extra_write_paths)


# Runtime harnesses: standalone scripts (they need the full Hermes CLI deps).
collect_ignore = ["runtime_test.py", "runtime_test_full.py"]
