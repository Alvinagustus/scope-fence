"""Tests for paths module."""
import os
import tempfile
import pytest
from pathlib import Path

import sys
sys.path.insert(0, os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), "..")))
from scope_fence.paths import resolve, is_inside, check_path
from conftest import SCRATCH


def test_resolve_absolute():
    p = resolve("/tmp/foo/bar")
    assert str(p) == os.path.realpath("/tmp/foo/bar")


def test_resolve_relative():
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        p = resolve("sub/file.txt", base=d)
        assert str(p) == os.path.realpath(os.path.join(d, "sub", "file.txt"))


def test_resolve_expanduser():
    p = resolve("~/test")
    assert str(p).startswith(os.path.expanduser("~"))


def test_is_inside_true():
    root = Path("/tmp/project")
    target = Path("/tmp/project/src/main.py")
    assert is_inside(target, [root]) is True


def test_is_inside_false():
    root = Path("/tmp/project-a")
    target = Path("/tmp/project-b/file.py")
    assert is_inside(target, [root]) is False


def test_is_inside_equal():
    root = Path("/tmp/project")
    assert is_inside(root, [root]) is True


def test_check_path_allowed():
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        scope = [resolve(d)]
        result = check_path(os.path.join(d, "file.txt"), scope, [])
        assert result is None


def test_check_path_outside():
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d1:
        with tempfile.TemporaryDirectory(dir=SCRATCH) as d2:
            scope = [resolve(d1)]
            result = check_path(os.path.join(d2, "file.txt"), scope, [])
            assert result is not None
            assert result[0] == "outside-scope"


def test_check_path_deny_wins():
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        ssh_dir = os.path.join(d, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        scope = [resolve(d)]
        deny = [resolve(ssh_dir)]
        result = check_path(os.path.join(ssh_dir, "id_rsa"), scope, deny)
        assert result is not None
        assert result[0] == "deny-list"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs elevated privileges on Windows")
def test_symlink_escape():
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        with tempfile.TemporaryDirectory(dir=SCRATCH) as outside:
            link = os.path.join(d, "link_out")
            os.symlink(outside, link)
            scope = [resolve(d)]
            # Writing through a symlink that points outside scope must be blocked
            result = check_path(os.path.join(link, "evil.txt"), scope, [])
            assert result is not None
            assert result[0] == "outside-scope"

def test_traversal():
    with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
        scope = [resolve(d)]
        result = check_path(os.path.join(d, "..", "other", "file.txt"), scope, [])
        assert result is not None
        assert result[0] == "outside-scope"


def test_posix_absolute_path_is_absolute_on_every_platform():
    """Review (Windows run): a leading separator is absolute even where os.path.isabs
    says otherwise — ntpath rejects `/outside/x`, but the shell treats it as the root."""
    from scope_fence.paths import is_abs_path
    assert is_abs_path("/outside/x") is True
    assert is_abs_path("/") is True
    assert is_abs_path("relative/path") is False
    assert is_abs_path(".") is False
    if os.name == "nt":
        assert is_abs_path("\\outside\\x") is True


def test_case_insensitive():
    # normcase is a no-op on Linux, lowercases on Windows — assert the invariant
    root = Path(os.path.normcase("/tmp/Project"))
    target = Path(os.path.normcase("/tmp/project/file.txt"))
    if os.name == "nt":
        assert is_inside(target, [root]) is True
    else:
        # Case-sensitive: different case is a different path
        assert is_inside(target, [root]) is False
