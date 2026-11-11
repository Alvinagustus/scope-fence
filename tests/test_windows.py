"""Windows-specific path handling.

Runs only on Windows (`pytest.mark.skipif`); on POSIX these are skipped. The rest of
the suite is platform-neutral, so this module is where Windows-only behaviour is
pinned down: drive letters, case-insensitive containment, separator handling and
filesystem-root detection.

The plugin documents two Windows limits, both asserted here:
- 8.3 short names are not expanded;
- PowerShell / cmd.exe syntax is not modelled (only POSIX shell syntax is).
"""
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows-only path handling")

from scope_fence.paths import check_path, is_filesystem_root, is_inside, resolve


def test_drive_letter_path_is_absolute():
    assert os.path.isabs("C:\\Users\\alvin\\project\\a.txt") is True
    assert os.path.isabs("D:/data/x") is True


def test_user_profile_expands():
    # ~ must resolve to the Windows user profile, not a POSIX home.
    assert "~" not in os.path.expanduser("~")
    assert os.path.isabs(os.path.expanduser("~\\project"))


def test_case_insensitive_containment():
    # normcase lowercases on Windows, so different case is the same path.
    root = Path("C:\\Users\\Alvin\\Project")
    target = Path("c:\\users\\alvin\\project\\file.txt")
    assert is_inside(target, [root]) is True


def test_separator_equivalence():
    a = resolve("C:\\Users\\alvin\\project\\a.txt")
    b = resolve("C:/Users/alvin/project/a.txt")
    assert a == b


def test_parent_traversal_resolves():
    assert resolve("C:\\Users\\alvin\\project\\..\\other") == Path("C:\\Users\\alvin\\other")


def test_filesystem_roots():
    assert is_filesystem_root("C:\\") is True
    assert is_filesystem_root("D:/") is True
    assert is_filesystem_root("\\\\server\\share") is True
    assert is_filesystem_root("C:\\Users\\alvin\\project") is False


def test_scope_check_with_windows_paths():
    root = resolve("C:\\Users\\alvin\\project")
    assert check_path("C:\\Users\\alvin\\project\\a.txt", [root], []) is None
    assert check_path("C:/Users/alvin/project/b.txt", [root], []) is None
    hit = check_path("C:\\Users\\alvin\\other\\a.txt", [root], [])
    assert hit is not None and hit[0] == "outside-scope"


def test_deny_wins_over_scope_on_windows():
    root = resolve("C:\\Users\\alvin\\project")
    deny = [resolve("C:\\Users\\alvin\\project\\secrets")]
    hit = check_path("C:\\Users\\alvin\\project\\secrets\\id_rsa", [root], deny)
    assert hit is not None and hit[0] == "deny-list"
