"""Terminal command classifier for scope-fence.

Guardrail, not a sandbox: it blocks writers that resolve outside the declared
scope. It does not attempt to analyse interpreter code or defeat deliberate
evasion (see README "What this is / is not").
"""
import os
import re
import shlex

from .paths import is_abs_path

# Writer/destructive verbs (normal mode)
DESTRUCTIVE_VERBS = ("rm", "git reset", "git clean", "git checkout", "git restore",
                     "find", "mv", "cp", "mkdir", "ln", "dd", "mkfs", "shred",
                     "chmod", "chown", "tee", "truncate", "install", "touch",
                     "sed", "perl", "python", "python3", "node", "ruby",
                     "php", "curl", "wget", "tar", "unzip", "rsync", "patch")

# Commands that are read-only by nature
READONLY_COMMANDS = ("ls", "cat", "grep", "pwd", "echo", "head", "tail", "wc",
                     "which", "type", "file", "stat", "du", "df", "env", "printenv")
READONLY_GIT = ("status", "log", "diff", "show")

SUBSTITUTION = re.compile(r"(\$\(|\$\{|\$\$\(|`)")
# Non-literal tokens: variables, special params, ANSI-C quoting, brace expansion
NON_LITERAL = re.compile(r"(\$\{?[A-Za-z_]|\\\$\(?|\$[0-9@*#?!$-]|\$'|\{)")
GLOB = re.compile(r"[*?]")
URL_SCHEME = re.compile(r"^(?:https?://|git@|ssh://|ftp://)")
DEV_NULL = re.compile(r"^/dev/(null|stdout|stderr|tty|zero|full|random|urandom)$")
REDIR_OP = re.compile(r"^[0-9]*(&?>|&>|\|>)$")

INTERPRETERS = ("bash", "sh", "zsh", "dash", "ksh", "fish",
                "python", "python3", "perl", "ruby", "node", "php", "lua", "awk")

REPO_STATE_GIT = ("git branch -d", "git branch -D", "git branch -m", "git branch -M",
                  "git remote add", "git remote remove", "git remote rename",
                  "git remote set-url", "git tag -d", "git tag --delete",
                  "git stash", "git apply", "git config")


def _join_quoted(toks: list) -> str:
    return " ".join(shlex.quote(t) for t in toks)


def _shell_script(seg: str):
    """If seg is `<shell> [flags] -c <script>`, return the script (quote-preserved).

    The -c/--command flag may sit anywhere in the flag cluster (`bash -i -c`,
    `bash --noprofile -c`, `sh -x -c`, `bash -lc`), so tokenize and walk the flags
    instead of regex-matching only the first flag.
    """
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return None
    if not toks:
        return None
    if toks[0].lower() not in ("sh", "bash", "zsh", "dash", "ksh", "fish"):
        return None
    # Long flags that take a separate value argument.
    _VALUE_FLAGS = {"--rcfile", "--init-file", "--login-file", "--output", "-o", "-O"}
    script_idx = None
    i = 1
    while i < len(toks):
        t = toks[i]
        if t == "--command" or t == "-c":
            script_idx = i + 1
            break
        if t.startswith("--"):
            i += 2 if t in _VALUE_FLAGS else 1
            continue
        if t.startswith("-") and len(t) > 1:
            if "c" in t[1:]:  # flag cluster containing c, e.g. -lc, -xc
                script_idx = i + 1
                break
            i += 2 if t in _VALUE_FLAGS else 1
            continue
        # A positional token before -c means this is not a `-c` form.
        break
    if script_idx is None or script_idx >= len(toks):
        return None
    # In shell semantics `-c` takes exactly one word as the command string.
    # Return it verbatim (unquoted) so the recursive classifier can re-parse it.
    return toks[script_idx]


def _strip_wrappers(seg: str, depth: int = 0) -> str:
    """Strip env/sudo/nohup/nice/time/command/exec/busybox/stdbuf/timeout wrappers."""
    if depth >= 3:
        return seg
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return seg
    if not toks:
        return seg
    first = toks[0].lower()
    if first == "env":
        i = 1
        while i < len(toks):
            t = toks[i]
            if t in ("-i", "--ignore-environment"):
                i += 1
                continue
            if t in ("-u", "--unset"):
                i += 2
                continue
            if t.startswith("-") or "=" in t:
                i += 1
                continue
            break
        if i < len(toks):
            return _strip_wrappers(_join_quoted(toks[i:]), depth + 1)
        return seg
    if first == "sudo":
        i = 1
        while i < len(toks):
            t = toks[i]
            if t.startswith("--"):
                i += 1
                continue
            if t.startswith("-") and len(t) == 2 and t[1] in "ugChpUrRtt":
                i += 2
                continue
            if t.startswith("-"):
                i += 1
                continue
            break
        if i < len(toks):
            return _strip_wrappers(_join_quoted(toks[i:]), depth + 1)
        return seg
    if first in ("nohup", "nice", "time", "command", "exec", "busybox", "stdbuf"):
        i = 1
        while i < len(toks) and toks[i].startswith("-"):
            i += 1
        if i < len(toks):
            return _strip_wrappers(_join_quoted(toks[i:]), depth + 1)
        return seg
    if first == "timeout":
        i = 1
        while i < len(toks) and toks[i].startswith("-"):
            i += 1
        if i < len(toks):
            i += 1  # duration
        if i < len(toks):
            return _strip_wrappers(_join_quoted(toks[i:]), depth + 1)
        return seg
    if first == "eval":
        if len(toks) > 1:
            return _strip_wrappers(toks[1], depth + 1)
        return seg
    return seg


def _unwrap_all(seg: str, depth: int = 0) -> str:
    """Recursively unwrap shell -c and command wrappers."""
    if depth >= 4:
        return seg
    new = seg
    script = _shell_script(seg)
    if script is not None and script != seg:
        new = script
    else:
        stripped = _strip_wrappers(seg)
        if stripped != seg:
            new = stripped
    if new != seg:
        return _unwrap_all(new, depth + 1)
    return seg


def _has_substitution(seg: str) -> bool:
    return bool(SUBSTITUTION.search(seg))


def _substitution_scripts(seg: str) -> list:
    """Extract the command strings inside `$(...)` and backticks (not `${...}`,
    which is parameter expansion, not command substitution)."""
    scripts = []
    i = 0
    while True:
        i = seg.find("$(", i)
        if i == -1:
            break
        depth = 1
        j = i + 2
        while j < len(seg) and depth > 0:
            c = seg[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        if depth == 0:
            scripts.append(seg[i + 2:j - 1])
        i = j if j > i else i + 1
    i = 0
    while True:
        i = seg.find("`", i)
        if i == -1:
            break
        j = seg.find("`", i + 1)
        if j == -1:
            break
        scripts.append(seg[i + 1:j])
        i = j + 1
    return scripts


def _is_readonly(seg: str) -> bool:
    """Read-only decision from the command word (never startswith on the whole segment)."""
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return False
    if not toks:
        return False
    first = toks[0].lower()
    readonly = first in READONLY_COMMANDS
    if not readonly and first == "git" and len(toks) > 1:
        sub = toks[1].lower()
        readonly = sub in READONLY_GIT and "--output" not in seg
    if not readonly and first == "find":
        # find is read-only unless it can write/delete: -exec/-execdir/-ok/-okdir/-delete/-fprint*
        readonly = not any(t in ("-delete", "-exec", "-execdir", "-ok", "-okdir")
                           or t.startswith("-fprint") for t in toks[1:])
    if not readonly:
        return False
    # Any redirection to a real file makes it a writer
    for i, t in enumerate(toks[1:], 1):
        if REDIR_OP.match(t):
            target = toks[i + 1] if i + 1 < len(toks) else ""
            if not DEV_NULL.match(target):
                return False
    return True


def _has_destructive_verb(seg: str) -> bool:
    """Token-based destructive-verb detection."""
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        toks = seg.split()
    if not toks:
        return False
    first = toks[0].lower()
    if first in ("rm", "mv", "cp", "mkdir", "ln", "dd", "mkfs", "shred",
                 "tee", "truncate", "install", "touch", "patch", "rsync"):
        return True
    if first in ("python", "python3", "node", "ruby", "php", "curl", "wget"):
        return True
    if first in ("sed", "perl"):
        return any(t.startswith("-i") or t.startswith("-p") for t in toks)
    if first in ("tar", "unzip"):
        return True
    if first in ("chmod", "chown"):
        return True
    if first == "find":
        # Read-only unless it can write/delete: -exec/-execdir/-ok/-okdir/-delete/-fprint*
        return any(t in ("-delete", "-exec", "-execdir", "-ok", "-okdir")
                   or t.startswith("-fprint") for t in toks)
    # Token-based git destructive detection
    for i, t in enumerate(toks):
        if t.lower() == "git":
            rest = " ".join(toks[i + 1:]).lower()
            for dg in ("git reset", "git clean", "git checkout", "git restore",
                       "git branch -d", "git branch -D", "git branch -m", "git branch -M",
                       "git remote add", "git remote remove", "git remote rename",
                       "git remote set-url", "git tag -d", "git tag --delete",
                       "git stash", "git apply", "git config"):
                sub = dg[4:]
                if rest == sub or rest.startswith(sub + " "):
                    return True
    return False


def _is_strict_destructive(seg: str) -> bool:
    """Strict-mode destructive set (narrower than DESTRUCTIVE_VERBS)."""
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        toks = seg.split()
    if not toks:
        return False
    first = toks[0].lower()
    if first in ("rm", "rmdir", "unlink", "mv", "cp", "ln", "dd", "shred",
                 "truncate", "rsync", "install", "mkdir", "mkfs", "mknod",
                 "chmod", "chown"):
        return True
    if first == "sed" and any(t.startswith("-i") for t in toks):
        return True
    if first == "find" and any(t in ("-delete", "-exec", "-execdir", "-ok", "-okdir")
                               or t.startswith("-fprint") for t in toks):
        return True
    if first == "git":
        rest = " ".join(toks[1:]).lower()
        for g in ("reset", "clean", "restore", "checkout", "stash", "apply"):
            if rest == g or rest.startswith(g + " "):
                return True
    return False


def _is_repo_state_git(seg: str) -> bool:
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        toks = seg.split()
    if not toks:
        return False
    for i, t in enumerate(toks):
        if t.lower() == "git":
            rest = " ".join(toks[i + 1:]).lower()
            for g in REPO_STATE_GIT:
                sub = g[4:]
                if rest == sub or rest.startswith(sub + " "):
                    return True
    return False


def _xargs_inner(seg: str):
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        toks = seg.split()
    if not toks or toks[0].lower() != "xargs":
        return None
    i = 1
    arg_flags = {"-I", "-i", "-n", "-s", "-P", "-d", "-a", "-E", "-e", "-L", "-l"}
    while i < len(toks):
        t = toks[i]
        if t in arg_flags:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        break
    if i < len(toks):
        return _join_quoted(toks[i:])
    return ""


def _find_exec_inner(seg: str):
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return None
    if not toks or toks[0].lower() != "find":
        return None
    for i, t in enumerate(toks[1:], 1):
        if t in ("-exec", "-execdir", "-ok", "-okdir"):
            rest = toks[i + 1:]
            inner = []
            for rt in rest:
                if rt in (";", "\\;", "+"):
                    break
                inner.append(rt)
            return (_join_quoted(inner), True)
    return None


def _split_segments(cmd: str) -> list:
    """Quote-aware scanner: split on unquoted newline, &, &&, ||, ;, |.

    Command substitutions ``$(...)`` and backticks are atomic — a separator inside
    them does not split the command (``echo $(rm x; echo y)`` is one segment).
    """
    segments = []
    current = ""
    in_single = False
    in_double = False
    paren_depth = 0
    in_backtick = False
    i = 0
    n = len(cmd)
    while i < n:
        c = cmd[i]
        # Backslash escape outside single quotes
        if c == "\\" and not in_single and i + 1 < n:
            current += c + cmd[i + 1]
            i += 2
            continue
        if in_backtick:
            current += c
            if c == "`":
                in_backtick = False
            i += 1
            continue
        # Inside a command substitution: track parens, do not split or toggle quotes.
        if not in_single and paren_depth > 0:
            if c == "(":
                paren_depth += 1
            elif c == ")":
                paren_depth -= 1
            current += c
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            current += c
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            current += c
            i += 1
            continue
        if not in_single:
            if cmd[i:i + 2] == "$(":
                paren_depth += 1
                current += "$("
                i += 2
                continue
            if c == "`" and not in_double:
                in_backtick = True
                current += c
                i += 1
                continue
            if not in_double:
                if cmd[i:i + 2] in ("&&", "||"):
                    segments.append(current.strip())
                    current = ""
                    i += 1
                elif c in ";|\n":
                    segments.append(current.strip())
                    current = ""
                elif c == "&":
                    # single & is a separator unless part of a redirection (> &)
                    if i > 0 and cmd[i - 1] == ">":
                        current += c
                    else:
                        segments.append(current.strip())
                        current = ""
                else:
                    current += c
            else:
                current += c
        else:
            current += c
        i += 1
    if current.strip():
        segments.append(current.strip())
    return [s for s in segments if s]


def _extract_paths_from_segment(seg: str, allow_placeholder: bool = False):
    """Extract path operands from a segment. Returns None if unverifiable."""
    paths = []
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return None
    if not toks:
        return paths

    # awk script: the script body is not a path; check redirection targets only
    if toks[0].lower() in ("awk", "gawk", "mawk"):
        for m in re.finditer(r"(?:>>?)\s*(\(?\s*[^;\s]+)", seg):
            target = m.group(1).strip("()")
            paths.append(target)
        return paths

    # Redirection targets (skip /dev/null*)
    for m in re.finditer(r"(?:>>?|2>|&>|>\|)\s*(\S+)", seg):
        target = m.group(1)
        if not DEV_NULL.match(target):
            paths.append(target)

    # --flag=value
    for m in re.finditer(r"--[\w-]+=(\S+)", seg):
        val = m.group(1)
        if val and not val.startswith("-"):
            paths.append(val)

    # Short options with an attached value that looks like a path: -o/path, -O/path, -f./x
    for t in toks:
        m = re.match(r"^-([a-zA-Z])(\S+)$", t)
        if not m:
            continue
        val = m.group(2)
        if "/" in val or val.startswith("~") or val.startswith("."):
            paths.append(val)

    # dd-style if=/of=
    for m in re.finditer(r"\b(?:if|of|seek|skip|conv|dir|output|input)=([^\s,]+)", seg):
        val = m.group(1)
        if val and not val.startswith("-"):
            paths.append(val)

    # git --git-dir= / --work-tree=
    for m in re.finditer(r"--git-dir=(\S+)", seg):
        paths.append(m.group(1))
    for m in re.finditer(r"--work-tree=(\S+)", seg):
        paths.append(m.group(1))

    for t in toks:
        if allow_placeholder and t == "{}":
            continue
        if NON_LITERAL.search(t):
            return None

    # Token operands: skip the command word (index 0), flags, VAR=value, redirections
    for idx, t in enumerate(toks):
        if idx == 0:
            continue
        if t.startswith("-"):
            continue
        if "=" in t and not t.startswith("/") and not URL_SCHEME.match(t):
            continue
        if REDIR_OP.match(t):
            continue
        prev = toks[idx - 1]
        if REDIR_OP.match(prev):
            # redirection target: already added above unless /dev/null
            continue
        paths.append(t)

    return paths


def _first_non_literal(cmd: str) -> str:
    m = SUBSTITUTION.search(cmd) or NON_LITERAL.search(cmd)
    return m.group(0) if m else str(cmd)[:40]


def _is_stdin_interpreter(seg: str) -> bool:
    """True only when an interpreter has no script, module or code argument."""
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        toks = seg.split()
    if not toks:
        return False
    first = toks[0].lower()
    if first not in INTERPRETERS:
        return False
    for t in toks[1:]:
        if not t.startswith("-"):
            return False  # script path / module argument
        if t in ("-c", "-e", "-r", "--command", "-m", "-V", "--version", "-h", "--help"):
            return False
        if t.startswith("-") and "c" in t[1:]:
            return False
    return True


def classify_terminal(command: str, workdir: str = None, tracked_cwd: str = None, depth: int = 0):
    """Returns (verdict, detail): 'allow' | 'block' | 'unparseable' | 'check'."""
    if not command or not isinstance(command, str):
        return ("allow", None)
    if depth > 3:
        return ("unparseable", str(command)[:40])

    cmd = command.strip()
    if not cmd:
        return ("allow", None)

    segments = _split_segments(cmd)
    if not segments:
        return ("allow", None)

    cwd = workdir or tracked_cwd
    all_paths = []

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue

        # sh -c <script>: classify the script recursively
        script = _shell_script(seg)
        if script is not None and script != seg:
            verdict, detail = classify_terminal(script, cwd, cwd, depth + 1)
            if verdict == "unparseable":
                return ("unparseable", detail)
            if verdict == "check":
                all_paths.extend(detail)
            continue

        seg = _unwrap_all(seg)

        # Substitution/variable in a WRITER segment → unverifiable
        if _has_substitution(seg) and _has_destructive_verb(seg):
            return ("unparseable", _first_non_literal(seg))

        # Destructive command inside $(...)/backticks → classify it recursively.
        # Read-only inner commands (echo $(date), echo $(basename /etc/passwd)) stay allowed.
        for inner in _substitution_scripts(seg):
            inner = inner.strip()
            if not inner or not _has_destructive_verb(inner):
                continue
            iv, idetail = classify_terminal(inner, cwd, cwd, depth + 1)
            if iv == "unparseable":
                return ("unparseable", idetail)
            if iv == "check" and isinstance(idetail, list):
                for p in idetail:
                    if cwd is None and not is_abs_path(p) and not p.startswith("~"):
                        return ("unparseable", p)
                    from .paths import resolve as _resolve
                    all_paths.append(str(_resolve(p, cwd)))

        # Bare interpreter reading stdin (pipe-to-shell) → unparseable
        if _is_stdin_interpreter(seg):
            return ("unparseable", seg[:40])

        # xargs: classify the inner command
        xargs_inner = _xargs_inner(seg)
        if xargs_inner is not None:
            if xargs_inner:
                inner = _unwrap_all(xargs_inner)
                if _has_substitution(inner) and _has_destructive_verb(inner):
                    return ("unparseable", seg[:40])
                if _is_stdin_interpreter(inner):
                    return ("unparseable", seg[:40])
                inner_paths = _extract_paths_from_segment(inner)
                if inner_paths is None:
                    return ("unparseable", seg[:40])
                if not inner_paths and _has_destructive_verb(inner):
                    return ("unparseable", seg[:40])
                for p in inner_paths:
                    if cwd is None and not is_abs_path(p) and not p.startswith("~"):
                        return ("unparseable", seg[:40])
                    from .paths import resolve as _resolve
                    all_paths.append(str(_resolve(p, cwd)))
            continue

        # find -exec: classify the inner command
        find_inner = _find_exec_inner(seg)
        if find_inner is not None:
            inner_cmd, _terminated = find_inner
            try:
                ftoks = shlex.split(seg, posix=True)
                for fi, ft in enumerate(ftoks):
                    if ft in ("-exec", "-execdir", "-ok", "-okdir"):
                        find_paths = ftoks[1:fi]
                        break
                else:
                    find_paths = []
            except ValueError:
                find_paths = []
            for fp in find_paths:
                if fp.startswith("-"):
                    continue
                from .paths import resolve as _resolve
                all_paths.append(str(_resolve(fp, cwd)))
            if inner_cmd:
                inner = _unwrap_all(inner_cmd)
                if _has_substitution(inner) and _has_destructive_verb(inner):
                    return ("unparseable", inner_cmd[:40])
                if _is_stdin_interpreter(inner):
                    return ("unparseable", inner_cmd[:40])
                inner_paths = _extract_paths_from_segment(inner, allow_placeholder=True)
                if inner_paths is None:
                    return ("unparseable", inner_cmd[:40])
                if not inner_paths and _has_destructive_verb(inner):
                    return ("unparseable", inner_cmd[:40])
                for p in inner_paths:
                    if cwd is None and not is_abs_path(p) and not p.startswith("~"):
                        return ("unparseable", inner_cmd[:40])
                    from .paths import resolve as _resolve
                    all_paths.append(str(_resolve(p, cwd)))
            continue

        # cd / pushd / git -C prefix
        cd_target = _parse_dir_prefix(seg)
        if cd_target is not None:
            target, rest = cd_target
            if NON_LITERAL.search(target) or GLOB.search(target) or target == "-":
                cwd = None  # unknown cwd
            else:
                from .paths import resolve
                cwd = str(resolve(target, cwd))
                if rest:
                    all_paths.append(cwd)
            if not rest:
                continue
            seg = rest

        # Read-only check
        if _is_readonly(seg):
            continue

        # Repo-state destructive git → always block
        if _is_repo_state_git(seg):
            return ("unparseable", seg[:40])

        # Extract paths
        paths = _extract_paths_from_segment(seg)
        if paths is None:
            return ("unparseable", _first_non_literal(seg))

        for p in paths:
            if cwd is None and not is_abs_path(p) and not p.startswith("~"):
                return ("unparseable", p)
            from .paths import resolve
            all_paths.append(str(resolve(p, cwd)))

    if all_paths:
        return ("check", all_paths)

    # Writer with no explicit paths → check against cwd
    if _has_destructive_verb(cmd):
        if cwd:
            from .paths import resolve
            all_paths.append(str(resolve(cwd)))
        return ("check", all_paths) if all_paths else ("unparseable", cmd[:40])

    return ("allow", None)


def _parse_dir_prefix(seg: str):
    """Return (target, rest) if seg starts with cd/pushd/git -C, else None."""
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return None
    if not toks:
        return None
    first = toks[0].lower()
    if first in ("cd", "pushd"):
        if len(toks) < 2:
            return None
        return toks[1], " ".join(toks[2:])
    if first == "git" and len(toks) >= 3 and toks[1] == "-C":
        return toks[2], " ".join(toks[3:])
    return None
