"""Path resolution and scope checking for scope-fence."""
import os
from pathlib import Path


def is_abs_path(p) -> bool:
    """Absolute on every platform.

    `os.path.isabs` on Windows returns False for a POSIX-style absolute path such as
    `/outside/x` (ntpath only accepts a drive or UNC prefix), yet the shell resolves
    that to the current drive's root. On Windows a leading separator therefore also
    counts as absolute; on POSIX `os.path.isabs` is already correct.
    """
    s = str(p)
    if os.path.isabs(s):
        return True
    return os.name == "nt" and s.startswith(("/", "\\"))


def resolve(p: str, base: str = None) -> Path:
    """Expand ~, resolve against base if relative, then realpath (symlinks, ..)."""
    p = os.path.expanduser(p)
    if is_abs_path(p):
        path = p
    else:
        path = os.path.join(base or os.getcwd(), p)
    return Path(os.path.realpath(path))


def is_inside(target: Path, roots: list) -> bool:
    """Check if target is inside any of the roots (case-insensitive on Windows)."""
    t = Path(os.path.normcase(str(target)))
    for r in roots:
        r = Path(os.path.normcase(str(r)))
        if t == r or _is_relative_to(t, r):
            return True
    return False


def _is_relative_to(child: Path, parent: Path) -> bool:
    """Python 3.9 compatible is_relative_to."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def is_filesystem_root(p) -> bool:
    """True if p is a filesystem root: POSIX /, Windows C:\\, or UNC \\\\server\\share."""
    if not p:
        return False
    s = str(p)
    if s in ("/", os.path.sep):
        return True
    try:
        from pathlib import PureWindowsPath
        wp = PureWindowsPath(s)
        if wp.drive and wp.drive.endswith(":") and not s.replace(wp.drive, "").strip("\\/"):
            return True
        if s.startswith("\\\\") and s.count("\\") <= 4:
            return True
    except Exception:
        pass
    return False


def check_path(target: str, scope_roots: list, deny: list, base: str = None, extra_roots: list = None):
    """Returns None if allowed, else (reason, resolved_target). Deny first.

    If neither scope_roots nor extra_roots is declared, no scope violation is
    reported (the deny-list is still checked).
    """
    resolved = resolve(target, base)
    if is_inside(resolved, deny):
        return ("deny-list", resolved)
    allowed = list(scope_roots) + list(extra_roots or [])
    if not allowed:
        return None
    if not is_inside(resolved, allowed):
        return ("outside-scope", resolved)
    return None
