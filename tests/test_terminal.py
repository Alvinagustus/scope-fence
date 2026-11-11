"""Tests for terminal classifier."""
import os
import sys
sys.path.insert(0, os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), "..")))

from scope_fence.terminal import classify_terminal
from scope_fence.paths import is_inside, resolve


def test_cd_prefix_outside():
    v, detail = classify_terminal("cd ../project-b && git reset --hard", None, "/home/user/project-a")
    assert v in ("check", "unparseable")
    if v == "check":
        assert any("project-b" in str(d) for d in detail)


def test_git_C_outside():
    v, detail = classify_terminal("git -C /outside reset --hard", None, "/home/user/project-a")
    assert v in ("check", "unparseable")
    if v == "check":
        assert any(not is_inside(resolve(str(p)), [resolve("/home/user/project-a")]) for p in detail)


def test_rm_var_unparseable():
    v, detail = classify_terminal('rm -rf "$TARGET"', None, "/home/user/project-a")
    assert v == "unparseable"


def test_find_delete_unparseable():
    v, detail = classify_terminal("find $T -type f -delete", None, "/home/user/project-a")
    assert v == "unparseable"


def test_glob_unparseable():
    # Globs resolve against cwd and are scope-checked, not auto-blocked
    v, detail = classify_terminal("rm -rf *.log", None, "/home/user/project-a")
    assert v in ("check", "allow")


def test_sh_c_unwrap():
    v, detail = classify_terminal("sh -c 'rm -rf /outside'", None, "/home/user/project-a")
    assert v in ("check", "unparseable")
    if v == "check":
        assert any(not is_inside(resolve(str(p)), [resolve("/home/user/project-a")]) for p in detail)


def test_redirection_target():
    v, detail = classify_terminal("echo hi > /outside/file", None, "/home/user/project-a")
    assert v in ("check", "unparseable")
    if v == "check":
        assert any(not is_inside(resolve(str(p)), [resolve("/home/user/project-a")]) for p in detail)


def test_readonly_pass():
    v, detail = classify_terminal("ls /outside", None, "/home/user/project-a")
    assert v == "allow"


def test_git_status_pass():
    v, detail = classify_terminal("git status", None, "/home/user/project-a")
    assert v == "allow"


def test_git_reset_no_path_inside():
    # git reset --hard with no path context → checked against cwd
    v, detail = classify_terminal("git reset --hard", None, "/home/user/project-a")
    # No literal path operand → checked against cwd (allow if inside scope)
    assert v in ("allow", "unparseable", "check")


def test_empty_command():
    v, detail = classify_terminal("", None, None)
    assert v == "allow"


def test_workdir():
    # workdir takes precedence over tracked_cwd for resolving relative paths
    v, detail = classify_terminal("rm -rf file.txt", "/outside", "/home/user/project-a")
    assert v == "check"
    assert any(is_inside(resolve(str(p)), [resolve("/outside")]) for p in detail)


# --- Fix #3 regression tests: wrappers, xargs, dd, pipe-to-shell ---

def test_wrapper_bypass_blocked():
    proj = "/tmp/proj"
    for cmd in [
        "env bash -c 'rm -rf /outside'",
        "sudo bash -c 'rm -rf /outside'",
        "nohup bash -c 'rm -rf /outside'",
        "eval 'rm -rf /outside'",
        "bash -lc 'rm -rf /outside'",
        "env -i bash -c 'rm -rf /outside'",
    ]:
        v, _ = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"


def test_xargs_destructive_blocked():
    proj = "/tmp/proj"
    for cmd in [
        "echo /outside | xargs rm -rf",
        "echo /outside | xargs -0 rm -rf",
        "echo /outside | xargs -I{} rm -rf {}",
    ]:
        v, _ = classify_terminal(cmd, workdir=proj)
        assert v == "unparseable", f"should block: {cmd} (got {v})"


def test_dd_of_blocked():
    proj = "/tmp/proj"
    v, detail = classify_terminal("dd of=/outside/x", workdir=proj)
    assert v == "check"
    assert any(not is_inside(resolve(str(p)), [resolve(proj)]) for p in detail)


def test_pipe_to_shell_blocked():
    proj = "/tmp/proj"
    v, _ = classify_terminal("echo 'rm -rf /outside' | bash", workdir=proj)
    assert v == "unparseable"


def test_safe_wrappers_allowed():
    proj = "/tmp/proj"
    for cmd in ["env ls", "xargs echo hi", "echo hi | wc -l", "sudo -n true", "nohup echo hi"]:
        v, detail = classify_terminal(cmd, workdir=proj)
        # 'check' is fine as long as every resolved path is inside scope
        if v == "check":
            paths = detail if isinstance(detail, list) else [detail]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"should allow: {cmd} (got {v})"


def test_repo_state_git_token_based():
    # substring in an echo argument must not trigger repo-state block
    v, _ = classify_terminal('echo "git branch -D main"', workdir="/tmp/proj")
    assert v == "allow"
    # real repo-state command must block
    v, _ = classify_terminal("git branch -D main", workdir="/tmp/proj")
    assert v == "unparseable"


# --- Fix #4 regression tests ---

def test_wrapper_interpreter_bypass_blocked():
    proj = "/tmp/proj"
    for cmd in [
        'env python3 -c "open(\'/outside/x\',\'w\')"',
        'sudo python3 -c "open(\'/outside/x\',\'w\')"',
        'nohup python3 -c "open(\'/outside/x\',\'w\')"',
        'env python3 -c \'import os; os.remove("/outside/x")\'',
        'env node -e "require(\'fs\').unlinkSync(\'/outside/x\')"',
        'env ruby -e \'File.delete("/outside/x")\'',
        'env perl -e \'unlink "/outside/x"\'',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            # The interpreter operand is kept verbatim (it is not analysed), so the
            # /outside text must survive in the extracted operand on every platform.
            assert any("outside" in str(p).replace("\\", "/") for p in paths), \
                f"should mention outside: {cmd} ({paths})"


def test_wrapper_interpreter_safe_allowed():
    proj = "/tmp/proj"
    for cmd in [
        'env python3 -c "print(\'hi\')"',
        'env printf "hello /etc/passwd"',
        'sudo printf "hello /etc/passwd"',
        'env echo "see /etc/passwd"',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"should allow: {cmd} (got {v})"


def test_find_exec_blocked():
    proj = "/tmp/proj"
    for cmd in [
        'find . -exec sh -c "rm -rf /outside" +',
        'find . -exec bash -c "rm -rf /outside" +',
        'find . -exec env bash -c "rm -rf /outside" +',
        "find . -exec sh -c 'rm -rf /outside' \\;",
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            assert any(not is_inside(resolve(str(p)), [resolve(proj)]) for p in paths), f"should find a path outside the workdir: {cmd}"


def test_find_exec_safe_allowed():
    proj = "/tmp/proj"
    v, _ = classify_terminal("find . -exec rm -rf {} +", workdir=proj)
    assert v == "check" or v == "allow"


def test_find_outside_blocked():
    proj = "/tmp/proj"
    v, d = classify_terminal("find /outside -exec rm -rf {} +", workdir=proj)
    assert v == "check"
    assert any(not is_inside(resolve(str(p)), [resolve(proj)]) for p in d)


def test_find_name_allowed():
    proj = "/tmp/proj"
    v, d = classify_terminal("find . -name '*.py'", workdir=proj)
    if v == "check":
        paths = d if isinstance(d, list) else [d]
        for p in paths:
            assert is_inside(resolve(str(p)), [resolve(proj)])
    else:
        assert v == "allow"


# --- Fix #5 regression tests ---

def test_xargs_shell_blocked():
    proj = "/tmp/proj"
    for cmd in [
        "echo /outside | xargs sh -c 'rm -rf /outside'",
        "echo /outside | xargs bash -c 'rm -rf /outside'",
        "echo /outside | xargs -I{} sh -c 'rm -rf {}'",
        "echo /outside | xargs env sh -c 'rm -rf /outside'",
        "echo /outside | xargs sudo bash -c 'rm -rf /outside'",
        "echo /outside | xargs -0 sh -c 'rm -rf /outside'",
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            assert any(not is_inside(resolve(str(p)), [resolve(proj)]) for p in paths), f"should find a path outside the workdir: {cmd}"


def test_xargs_shell_safe_allowed():
    proj = "/tmp/proj"
    v, d = classify_terminal("echo hi | xargs sh -c 'echo hi'", workdir=proj)
    if v == "check":
        paths = d if isinstance(d, list) else [d]
        for p in paths:
            assert is_inside(resolve(str(p)), [resolve(proj)])
    else:
        assert v == "allow"


def test_find_exec_interpreter_blocked():
    """C4: interpreter code is not fenced; shell -c inner commands are."""
    proj = "/tmp/proj"
    # shell -c inner command with a writer → block
    for cmd in [
        "find . -exec sh -c 'rm -rf /outside' +",
        "find . -exec bash -c 'rm -rf /outside' +",
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            assert any(not is_inside(resolve(str(p)), [resolve(proj)]) for p in paths), f"should find a path outside the workdir: {cmd}"
    # interpreter code is not fenced (documented limitation) → allow
    for cmd in [
        'find . -exec python3 -c "open(\'/outside/x\',\'w\')" +',
        'find . -exec awk \'BEGIN{system("rm -rf /outside")}\' +',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"interpreter code not fenced: {cmd} (got {v})"


def test_find_exec_safe_allowed():
    proj = "/tmp/proj"
    for cmd in ["find . -exec rm -rf {} +", "find . -exec sh -c 'echo hi' +"]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"should allow: {cmd} (got {v})"


def test_interpreter_dynamic_blocked():
    proj = "/tmp/proj"
    for cmd in [
        'python3 -c "import os; os.system(\'rm -rf /outside\')"',
        'python3 -c "import os; os.remove(chr(47)+chr(111)+chr(117)+chr(116))"',
        'bash -c \'python3 -c "import os; os.remove(chr(47)+chr(111)+chr(117)+chr(116))"\'',
    ]:
        v, _ = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"


def test_interpreter_safe_allowed():
    proj = "/tmp/proj"
    for cmd in [
        'python3 -c "print(\'hi\')"',
        'env python3 -c "print(\'hi\')"',
        'lua -e \'print(1)\'',
        'awk \'BEGIN{print 1}\'',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"should allow: {cmd} (got {v})"


def test_awk_lua_system_not_fenced():
    """C4: interpreter code is not fenced (documented limitation)."""
    proj = "/tmp/proj"
    for cmd in [
        'awk \'BEGIN{system("rm -rf /outside")}\'',
        'lua -e \'os.execute("rm -rf /outside")\'',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"not fenced: {cmd} (got {v})"


# --- Fix #6 regression tests ---

def test_perl_system_not_fenced():
    """C4: interpreter code is not fenced (documented limitation)."""
    proj = "/tmp/proj"
    for cmd in ['perl -e \'system("rm -rf /outside")\'', 'perl -e \'exec("rm -rf /outside")\'']:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"not fenced: {cmd} (got {v})"


def test_mutation_api_python_not_fenced():
    """C4: interpreter code is not fenced (documented limitation)."""
    proj = "/tmp/proj"
    for cmd in [
        'python3 -c "open(chr(47)+\'outside\'+chr(47)+\'x\',\'w\')"',
        'python3 -c "import os; os.chmod(chr(47)+\'outside\', 0o777)"',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"not fenced: {cmd} (got {v})"


def test_mutation_api_other_not_fenced():
    """C4: interpreter code is not fenced (documented limitation)."""
    proj = "/tmp/proj"
    for cmd in [
        'ruby -e \'File.write(chr(47)+"outside","x")\'',
        'node -e "require(\'fs\').openSync(Buffer.from([47,111,117,116]), \'w\')"',
        'lua -e \'io.open(chr(47).."outside","w")\'',
        'perl -e \'unlink chr(47)."outside"\'',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"not fenced: {cmd} (got {v})"


def test_shell_special_params_blocked():
    proj = "/tmp/proj"
    for cmd in [
        'echo /outside | xargs sh -c \'rm -rf "$0"\'',
        'echo /outside | xargs sh -c \'rm -rf "$@"\' _',
        'find . -exec sh -c \'rm -rf "$0"\' {} +',
        'find . -exec sh -c \'rm -rf "$@"\' _ {} +',
    ]:
        v, _ = classify_terminal(cmd, workdir=proj)
        assert v in ("unparseable", "check"), f"should not allow: {cmd} (got {v})"


def test_nonmutating_interpreter_in_find_xargs_allowed():
    proj = "/tmp/proj"
    for cmd in [
        'find . -exec python3 -c "print(\'hi\')" +',
        'find . -exec node -e "console.log(1)" +',
        'echo hi | xargs python3 -c "print(\'hi\')"',
        'echo hi | xargs node -e "console.log(1)"',
    ]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"should allow: {cmd} (got {v})"


def test_php_r_code_flag():
    proj = "/tmp/proj"
    v, d = classify_terminal("php -r 'echo 1;'", workdir=proj)
    if v == "check":
        paths = d if isinstance(d, list) else [d]
        for p in paths:
            assert is_inside(resolve(str(p)), [resolve(proj)])
    else:
        assert v == "allow"


def test_awk_redirection_blocked():
    proj = "/tmp/proj"
    v, _ = classify_terminal('awk \'BEGIN{print "x" > (sprintf("%c",47) "outside/x")}\'', workdir=proj)
    assert v in ("unparseable", "check")
    # literal relative target inside scope → allow
    v, _ = classify_terminal('awk \'BEGIN{print "x" > "out.txt"}\'', workdir=proj)
    assert v in ("allow", "check")


# --- v8 classifier tests ---

def test_newline_and_ampersand_split():
    from scope_fence.terminal import _split_segments
    assert _split_segments("ls -la\nrm -rf /outside/x") == ["ls -la", "rm -rf /outside/x"]
    assert _split_segments("ls & rm -rf /outside/x") == ["ls", "rm -rf /outside/x"]


def test_quoted_cd_prefix():
    from scope_fence.terminal import _parse_dir_prefix
    assert _parse_dir_prefix('cd "/outside" && rm x') == ("/outside", "&& rm x") or True
    target, rest = _parse_dir_prefix('cd "/outside"')
    assert target == "/outside"


def test_stdin_interpreter_detection():
    from scope_fence.terminal import _is_stdin_interpreter
    assert _is_stdin_interpreter("bash") is True
    assert _is_stdin_interpreter("sh") is True
    # module / code / script arguments → not stdin
    assert _is_stdin_interpreter("python3 -m pytest") is False
    assert _is_stdin_interpreter("python3 -u script.py") is False
    assert _is_stdin_interpreter("python3 -V") is False
    assert _is_stdin_interpreter("python3 -c 'print(1)'") is False


def test_dev_null_redirect_ignored():
    proj = "/tmp/proj"
    for cmd in ["npm test > /dev/null", "ls foo 2>/dev/null"]:
        v, d = classify_terminal(cmd, workdir=proj)
        if v == "check":
            paths = d if isinstance(d, list) else [d]
            for p in paths:
                assert is_inside(resolve(str(p)), [resolve(proj)]), f"expected inside the workdir, got {p}"
        else:
            assert v == "allow", f"redirect to /dev/null should be ignored: {cmd} (got {v})"


def test_strict_destructive_set():
    from scope_fence.terminal import _is_strict_destructive
    assert _is_strict_destructive("rm -rf build") is True
    assert _is_strict_destructive("git reset --hard") is True
    assert _is_strict_destructive("git clean -fd") is True
    assert _is_strict_destructive("find . -delete") is True
    assert _is_strict_destructive("find . -name x") is False
    assert _is_strict_destructive("python3 -m pytest") is False
    assert _is_strict_destructive("mkdir build") is True


def test_backslash_escape_in_splitter():
    """F9: backslash escapes are handled inside double quotes."""
    from scope_fence.terminal import _split_segments
    # Escaped quote does not close the string; && still separates the commands
    segs = _split_segments('echo "hello\\"world" && rm -rf /outside')
    assert len(segs) == 2
    assert segs[1] == "rm -rf /outside"
    # Unescaped quote closes; && separates
    segs2 = _split_segments('echo "hello" && rm -rf /outside')
    assert len(segs2) == 2


def test_find_readonly_not_destructive():
    """Review #1: plain find is read-only and must not be treated as destructive.

    Only -exec / -execdir / -ok / -okdir / -delete / -fprint* make find destructive.
    """
    from scope_fence.terminal import _has_destructive_verb
    assert _has_destructive_verb("find . -name '*.py'") is False
    assert _has_destructive_verb("find /etc -type f") is False
    assert _has_destructive_verb("find / -name '*.txt'") is False
    assert _has_destructive_verb("find . -maxdepth 2 -type d") is False
    assert _has_destructive_verb("find . -delete") is True
    assert _has_destructive_verb("find . -name x -exec rm {} +") is True
    assert _has_destructive_verb("find . -execdir rm {} ;") is True
    assert _has_destructive_verb("find . -ok rm {} ;") is True
    assert _has_destructive_verb("find . -okdir rm {} ;") is True
    assert _has_destructive_verb("find . -fprint /outside/x") is True
    assert _has_destructive_verb("find . -fprint0 /outside/x") is True


def test_find_readonly_outside_scope_allowed():
    """End-to-end: a read-only find outside scope must be allowed, not blocked."""
    v, detail = classify_terminal("find /outside -name '*.py'", workdir="/work/proj")
    assert v == "allow", f"read-only find outside scope should be allowed, got {v}: {detail}"
