"""Hook handlers for scope-fence."""
import json
import logging
import os
import re
import threading
import time
from pathlib import Path

from .paths import check_path, resolve, is_inside, is_filesystem_root, is_abs_path
from .terminal import classify_terminal, _split_segments, _is_strict_destructive
from .store import get_scope, record_block, record_cwd, prune_session, invalidate_cache
from .config import load_config, extra_write_roots, mode as get_mode

log = logging.getLogger(__name__)

FILE_TOOLS = {"write_file": "path", "patch": "path", "skill_manage": "file_path"}
GUARDED_TOOLS = {"write_file", "patch", "skill_manage", "terminal"}
READ_TOOLS = {"read_file", "search_files"}
SKILL_READ_ACTIONS = {"list", "view", "read", "search", "get"}

# Commands that only print/resolve the path they mention — they cannot read or write it.
# `env` is deliberately NOT here: it executes its arguments, so `env rm ~/.ssh/id_rsa`
# must still be deny-checked.
_NO_FILE_ACCESS_COMMANDS = {
    "echo", "printf", "pwd", "which", "type", "printenv", "true", "false",
    "date", "whoami", "id", "uname", "hostname", "uptime", "clear", "cal",
    "basename", "dirname", "realpath", "readlink",
}

_PATH_TOKEN_RE = re.compile(r"(['\"]?)((?:/|\./|~/)[\w./~+\-]+)\1")
_REDIRECT_RE = re.compile(r"(?:>>?|&>|[0-9]+>)\s*(\S+)")

_RECOVERY_LINE = ("Do not retry this command or work around it with another command. "
                  "Ask the user to run /scope add <dir>, or continue inside the scope.")

# Circuit breaker: 3 consecutive internal errors open the fence for 60 seconds.
_BREAKER = {"errors": 0, "open_until": 0.0, "last_error": ""}
_BREAKER_LOCK = threading.Lock()
_BREAKER_THRESHOLD = 3
_BREAKER_OPEN_SECONDS = 60.0

# Process-lifetime counters for /scope doctor.
_STATS = {
    "pre_tool_call": 0, "with_session_id": 0, "with_conversation_id": 0, "with_neither": 0,
    "post_tool_call": 0, "post_compaction": 0, "session_reset": 0, "session_finalize": 0,
    "section_render": 0,
}
_STATS_LOCK = threading.Lock()


def get_stats() -> dict:
    """Process-lifetime hook counters (for /scope doctor). Never raises."""
    with _STATS_LOCK:
        return dict(_STATS)


def get_breaker_state() -> dict:
    """Read-only breaker state (for /scope doctor). Never raises."""
    with _BREAKER_LOCK:
        now = time.time()
        return {
            "errors": _BREAKER["errors"],
            "open": bool(_BREAKER["open_until"] and now < _BREAKER["open_until"]),
            "last_error": _BREAKER["last_error"][:200],
        }


def _bump(key: str):
    with _STATS_LOCK:
        _STATS[key] = _STATS.get(key, 0) + 1


def _clip(s, n: int = 200) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def _finalize_message(msg: str) -> str:
    """Keep block messages at most 600 chars, preserving the recovery line."""
    if len(msg) <= 600:
        return msg
    lines = msg.split("\n")
    head = lines[0] if lines else ""
    tail = lines[-1] if len(lines) > 1 else ""
    out = head + "\n...\n" + tail
    return out if len(out) <= 600 else out[:597] + "..."


def _veto(reason, tool_name, resolved, scope, message, session_id, conversation_id=""):
    """The single block site. The deny-list is always enforced; `mode` affects the rest."""
    msg = _finalize_message(message)
    if reason != "deny-list" and get_mode() == "warn":
        try:
            record_block(session_id, tool_name, _clip(resolved), "would-block:" + reason,
                         conversation_id=conversation_id)
        except Exception:
            pass
        log.warning("scope-fence: [warn] would have blocked %s %s (%s)", tool_name, resolved, reason)
        return None
    try:
        record_block(session_id, tool_name, _clip(resolved), reason, conversation_id=conversation_id)
    except Exception:
        pass
    return {"action": "block", "message": msg}


# One-shot warnings (G2 / G7)
_NO_SESSION_WARNED = False
_INACTIVE_WARNED = set()
_AUTO_SCOPE_FAILED = {}
_AUTO_SCOPE_LOCK = threading.Lock()


def _skills_root() -> Path:
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home()) / "skills"
    except Exception:
        return Path(os.path.expanduser("~/.hermes/skills"))


def _warn_no_session():
    global _NO_SESSION_WARNED
    if not _NO_SESSION_WARNED:
        log.warning("scope-fence: call without session id is not fenced")
        _NO_SESSION_WARNED = True


def _warn_inactive(session_id):
    if session_id in _INACTIVE_WARNED:
        return
    _INACTIVE_WARNED.add(session_id)
    log.warning("scope-fence: no scope declared for session %r; fence inactive", session_id)


def _reset_warnings(session_id: str = ""):
    """Clear per-session warning state (called on reset/finalize)."""
    _INACTIVE_WARNED.discard(session_id)
    with _AUTO_SCOPE_LOCK:
        if session_id:
            for key in [k for k in _AUTO_SCOPE_FAILED if k[0] == session_id]:
                del _AUTO_SCOPE_FAILED[key]
        else:
            _AUTO_SCOPE_FAILED.clear()


def _is_strict_destructive_command(command: str) -> bool:
    """Strict-mode destructiveness computed per segment."""
    for seg in _split_segments(command):
        if _is_strict_destructive(seg):
            return True
    return False


def _add_skill_paths(op: dict, paths: list):
    """Resolve a skill_manage operation to a writable path."""
    fp = op.get("file_path")
    name = op.get("name", "")
    root = _skills_root()
    if isinstance(fp, str) and fp:
        if is_abs_path(fp) or fp.startswith("~"):
            paths.append(fp)
        elif name:
            paths.append(str(root / name / fp))
        else:
            paths.append(str(root / fp))
    elif name:
        paths.append(str(root / name / "SKILL.md"))


def _collect_write_paths(tool_name: str, args: dict) -> list:
    """Extract write-target paths from write_file / patch / skill_manage args."""
    key = FILE_TOOLS.get(tool_name, "path")
    paths = []
    if tool_name == "patch":
        patch_content = args.get("patch", "")
        if isinstance(patch_content, str):
            for line in patch_content.split("\n"):
                line = line.strip()
                for marker in ("*** Add File:", "*** Update File:", "*** Delete File:"):
                    if line.startswith(marker):
                        fpath = line.split(":", 1)[-1].strip()
                        if fpath:
                            paths.append(fpath)
                        break
                else:
                    # V4A move header is `*** Move File: a -> b` — check BOTH sides.
                    if line.startswith("*** Move File:"):
                        value = line.split(":", 1)[-1].strip()
                        parts = [p.strip() for p in value.split(" -> ", 1)] if " -> " in value else [value]
                        for part in parts:
                            if part:
                                paths.append(part)
    elif tool_name == "skill_manage":
        action = args.get("action", "")
        ops = args.get("operations", [])
        if isinstance(ops, list) and ops:
            for op in ops:
                if isinstance(op, dict):
                    _add_skill_paths(op, paths)
        elif action and action not in SKILL_READ_ACTIONS:
            _add_skill_paths(args, paths)
    if not paths:
        path = args.get(key)
        if isinstance(path, str) and path:
            paths.append(path)
    return paths


def _deny_for_tool(tool_name: str, deny: list) -> list:
    """Deny-list entries that apply to a tool.

    `skill_manage` is a Hermes-mediated, name-validated write to the skills dir, so a
    deny entry that covers that directory must not make skill management impossible.
    Raw `write_file`/`patch` writes to the same place stay blocked.
    """
    if tool_name != "skill_manage":
        return deny
    skills_root = _skills_root()
    # Compare resolved paths (not raw strings), and treat an entry that CONTAINS the
    # skills dir as the Hermes-home entry it really is — with a profile, HERMES_HOME is
    # `<home>/.hermes/profiles/<profile>` while the default deny entry is `<home>/.hermes`.
    return [d for d in deny if not is_inside(skills_root, [resolve(str(d))])]


def _segment_touches_no_file(seg: str) -> bool:
    """True when the segment's command word cannot read or write the path it mentions."""
    try:
        import shlex
        toks = shlex.split(seg, posix=True)
    except ValueError:
        return False
    return bool(toks) and toks[0].lower() in _NO_FILE_ACCESS_COMMANDS


def _terminal_deny_hit(command: str, deny_resolved: list, base=None):
    """Regex scan for deny-listed path-like tokens.

    For commands that cannot touch files (`echo`, `printf`, ...) only redirect targets
    are checked — mentioning a path is not a violation, but `echo x > ~/.ssh` is.
    Relative tokens resolve against `base` (session CWD), never the process CWD.
    """
    from .terminal import NON_LITERAL
    for seg in _split_segments(command):
        if _segment_touches_no_file(seg):
            candidates = _REDIRECT_RE.findall(seg)
        else:
            candidates = [m.group(2).rstrip(".,;:)]}") for m in _PATH_TOKEN_RE.finditer(seg)]
        for tok in candidates:
            if not tok or NON_LITERAL.search(tok):
                continue
            try:
                rp = resolve(tok, base=base)
            except Exception:
                continue
            if is_inside(rp, deny_resolved):
                return rp
    return None


def _block_message(tool_name, resolved, scope, reason):
    scope_line = ", ".join(str(p) for p in scope["roots"]) or "(none)"
    if reason == "deny-list":
        reason_text = "target is on the deny-list."
    elif reason == "outside-scope":
        reason_text = "write outside the declared scope."
    else:
        reason_text = reason
    return "\n".join([
        "⛔ Scope Fence blocked this call.",
        f"Tool: {tool_name} · Target: {_clip(resolved, 120)} ({reason})",
        f"Scope: {_clip(scope_line, 150)}",
        f"Reason: {reason_text}",
        _RECOVERY_LINE,
    ])


def _unparseable_message(command, operand, scope):
    scope_line = ", ".join(str(p) for p in scope["roots"]) or "(none)"
    return "\n".join([
        "⛔ Scope Fence blocked this call.",
        f"Tool: terminal · Command: {_clip(command, 120)}",
        f"Scope: {_clip(scope_line, 150)}",
        f"Reason: destructive command could not be verified against the scope "
        f"(unparseable operand: {_clip(operand, 80)}). Run it yourself, or confirm the exact path first.",
        _RECOVERY_LINE,
    ])


def _strict_message(command, scope):
    scope_line = ", ".join(str(p) for p in scope["roots"])
    return "\n".join([
        "⛔ Scope Fence (strict mode) blocked this call.",
        f"Tool: terminal · Command: {_clip(command, 120)}",
        f"Scope: {_clip(scope_line, 150)}",
        "Reason: destructive command blocked by strict mode.",
        _RECOVERY_LINE,
    ])


def _try_git_root(cwd, session_id: str = ""):
    """Return the git root for cwd, or None.

    Failures are cached per (session, cwd) and expire after 60 seconds, so a later
    `git init` is picked up without a global clear.
    """
    if not cwd:
        return None
    key = (session_id or "", str(cwd))
    now = time.time()
    with _AUTO_SCOPE_LOCK:
        exp = _AUTO_SCOPE_FAILED.get(key)
        if exp is not None:
            if now < exp:
                return None
            del _AUTO_SCOPE_FAILED[key]
    try:
        import subprocess
        result = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                                cwd=cwd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            root = result.stdout.strip()
            if root:
                return root
    except Exception:
        pass
    with _AUTO_SCOPE_LOCK:
        _AUTO_SCOPE_FAILED[key] = now + 60.0
    return None


def _handle_internal_error(e, tool_name, session_id, conversation_id=""):
    """Circuit breaker: errors 1-2 fail closed; the 3rd opens the fence for 60s."""
    msg = str(e)[:200]
    opened = False
    with _BREAKER_LOCK:
        _BREAKER["errors"] += 1
        _BREAKER["last_error"] = msg
        if _BREAKER["errors"] >= _BREAKER_THRESHOLD:
            _BREAKER["open_until"] = time.time() + _BREAKER_OPEN_SECONDS
            opened = True
    if opened:
        log.warning("scope-fence: internal errors, fence temporarily disabled (60s): %s", msg)
        try:
            record_block(session_id, tool_name, msg, "breaker-open", conversation_id=conversation_id)
        except Exception:
            pass
        return None
    try:
        record_block(session_id, tool_name, msg, "hook-error", conversation_id=conversation_id)
    except Exception:
        pass
    return {"action": "block", "message": f"⛔ Scope Fence internal error: {msg}\nCheck /scope check for details."}


def _breaker_open() -> bool:
    with _BREAKER_LOCK:
        if _BREAKER["open_until"] and time.time() < _BREAKER["open_until"]:
            return True
        if _BREAKER["open_until"] and time.time() >= _BREAKER["open_until"]:
            _BREAKER["errors"] = 0
            _BREAKER["open_until"] = 0.0
        return False


def _breaker_open_deny_check(tool_name, args, session_id, conversation_id=""):
    """Breaker is open (fence fails open), but the deny-list still applies.

    Uses only in-memory config and plain path resolution — no DB access. If the check
    itself raises, fail open.
    """
    try:
        cfg = load_config()
        deny = [os.path.expanduser(p) for p in cfg["deny_paths"]]
        deny_resolved = [resolve(str(p)) for p in deny]
        empty_scope = {"roots": [], "deny": deny_resolved, "cwd": None}
        if tool_name in FILE_TOOLS:
            tool_deny = _deny_for_tool(tool_name, deny_resolved)
            for p in _collect_write_paths(tool_name, args):
                resolved = resolve(p)
                if is_inside(resolved, tool_deny):
                    return _veto("deny-list", tool_name, resolved, empty_scope,
                                 _block_message(tool_name, resolved, empty_scope, "deny-list"),
                                 session_id, conversation_id)
        elif tool_name == "terminal" and isinstance(args, dict):
            command = args.get("command")
            if isinstance(command, str):
                hit = _terminal_deny_hit(command, deny_resolved, args.get("workdir"))
                if hit is not None:
                    return _veto("deny-list", tool_name, hit, empty_scope,
                                 _block_message(tool_name, hit, empty_scope, "deny-list"),
                                 session_id, conversation_id)
    except Exception as e:
        log.warning("scope-fence: breaker-open deny check failed, failing open: %s", e)
    return None


def _no_scope_terminal_deny(command, workdir, scope, deny_resolved):
    """With no scope, deny-check the paths the classifier extracts (redirect targets,
    wrapper arguments). Falls back to the regex scan when classification is unparseable."""
    try:
        verdict, detail = classify_terminal(command, workdir, scope.get("cwd"))
    except Exception:
        verdict, detail = "unparseable", command
    if verdict == "check":
        paths = detail if isinstance(detail, list) else [detail]
        for p in paths:
            try:
                rp = resolve(str(p))
            except Exception:
                continue
            if is_inside(rp, deny_resolved):
                return rp
        return None
    if verdict == "unparseable":
        return _terminal_deny_hit(command, deny_resolved)
    return None


def _pre_tool_call_impl(tool_name, args, session_id, conversation_id):
    if not isinstance(args, dict):
        log.warning("scope-fence: pre_tool_call payload is not a dict (tool=%r); cannot verify", tool_name)
        return None

    cfg = load_config()
    read_gating = not cfg.get("allow_reads_outside_scope", True)

    # D3: return early for tools the fence does not guard
    if tool_name not in GUARDED_TOOLS and not (read_gating and tool_name in READ_TOOLS):
        return None

    # G2: no session context → warn once, do not fence
    if not session_id and not conversation_id:
        _warn_no_session()
        return None

    scope = get_scope(session_id, conversation_id)

    deny = [os.path.expanduser(p) for p in cfg["deny_paths"]]
    deny_resolved = [resolve(str(p)) for p in deny]
    extra = extra_write_roots()

    # --- deny-list checks (enforced in both modes) ---
    if tool_name in FILE_TOOLS:
        tool_deny = _deny_for_tool(tool_name, deny_resolved)
        for p in _collect_write_paths(tool_name, args):
            resolved = resolve(p, base=scope.get("cwd"))
            if is_inside(resolved, tool_deny):
                return _veto("deny-list", tool_name, resolved, scope,
                             _block_message(tool_name, resolved, scope, "deny-list"),
                             session_id, conversation_id)

    if tool_name == "terminal":
        command = args.get("command", "")
        if isinstance(command, str):
            base = scope.get("cwd") or args.get("workdir")
            hit = _terminal_deny_hit(command, deny_resolved, base)
            if hit is not None:
                return _veto("deny-list", tool_name, hit, scope,
                             _block_message(tool_name, hit, scope, "deny-list"),
                             session_id, conversation_id)

    # --- fence inactive if no scope declared ---
    if not scope["roots"]:
        if cfg.get("auto_scope", False):
            cwd = scope.get("cwd") or os.getcwd()
            home = os.path.realpath(os.path.expanduser("~"))
            real_cwd = os.path.realpath(str(cwd))
            if cwd and not is_filesystem_root(cwd) and real_cwd != home:
                git_root = _try_git_root(cwd, session_id)
                if git_root:
                    from .store import add_scope
                    add_scope(session_id, [git_root], conversation_id)
                    try:
                        record_block(session_id, "auto-scope", str(git_root), "auto-scope",
                                     conversation_id=conversation_id)
                    except Exception:
                        pass
                    log.info("scope-fence: auto-scoped session %r to %s", session_id, git_root)
                    invalidate_cache(session_id, conversation_id)
                    scope = get_scope(session_id, conversation_id)
        if not scope["roots"]:
            if cfg.get("deny_by_default", False):
                return _veto("deny_by_default", tool_name, "-", scope,
                             "⛔ Scope Fence: no scope declared. Use /scope add <dir> to enable.",
                             session_id, conversation_id)
            # With no scope the classifier still runs: its extracted paths (redirect
            # targets, wrapper arguments) are deny-checked, so the deny-list holds even
            # when no scope is declared.
            if tool_name == "terminal" and isinstance(args.get("command"), str):
                no_scope_hit = _no_scope_terminal_deny(args.get("command"), args.get("workdir"),
                                                       scope, deny_resolved)
                if no_scope_hit is not None:
                    return _veto("deny-list", tool_name, no_scope_hit, scope,
                                 _block_message(tool_name, no_scope_hit, scope, "deny-list"),
                                 session_id, conversation_id)
            _warn_inactive(session_id)
            return None

    # --- file tools scope check ---
    if tool_name in FILE_TOOLS and scope["roots"]:
        paths_to_check = _collect_write_paths(tool_name, args)
        # allow_skill_writes skips only the scope check, never the deny check
        if tool_name == "skill_manage" and cfg.get("allow_skill_writes", False):
            paths_to_check = []
        for p in paths_to_check:
            tool_deny = _deny_for_tool(tool_name, scope["deny"])
            hit = check_path(p, scope["roots"], tool_deny, base=scope["cwd"], extra_roots=extra)
            if hit:
                reason, resolved = hit
                return _veto(reason, tool_name, resolved, scope,
                             _block_message(tool_name, resolved, scope, reason),
                             session_id, conversation_id)

    # --- terminal ---
    if tool_name == "terminal":
        command = args.get("command")
        if not isinstance(command, str):
            return None
        verdict, detail = classify_terminal(command, args.get("workdir"), scope["cwd"])
        if verdict == "allow":
            if cfg.get("strict_mode", False) and _is_strict_destructive_command(command):
                return _veto("strict-mode", tool_name, command, scope,
                             _strict_message(command, scope), session_id, conversation_id)
            return None
        if verdict == "unparseable":
            if not cfg.get("block_unparseable_destructive", True) and not _is_strict_destructive_command(command):
                return None
            return _veto("unparseable", tool_name, command, scope,
                         _unparseable_message(command, detail, scope), session_id, conversation_id)
        paths_to_check = detail if isinstance(detail, list) else [detail]
        for p in paths_to_check:
            hit = check_path(p, scope["roots"], scope["deny"], extra_roots=extra)
            if hit:
                reason, resolved = hit
                return _veto(reason, tool_name, resolved, scope,
                             _block_message(tool_name, resolved, scope, reason),
                             session_id, conversation_id)
        if cfg.get("strict_mode", False) and _is_strict_destructive_command(command):
            return _veto("strict-mode", tool_name,
                         paths_to_check[0] if paths_to_check else command, scope,
                         _strict_message(command, scope), session_id, conversation_id)
        return None

    # --- read gating (opt-in) ---
    if tool_name in READ_TOOLS and read_gating:
        path = args.get("path") or args.get("target_dir")
        if isinstance(path, str) and path:
            hit = check_path(path, scope["roots"], scope["deny"])
            if hit:
                reason, resolved = hit
                return _veto(reason, tool_name, resolved, scope,
                             _block_message(tool_name, resolved, scope, reason),
                             session_id, conversation_id)

    return None


def on_pre_tool_call(tool_name: str = "", args=None, session_id: str = "", conversation_id: str = "", **kwargs):
    """Block writes/destructive commands outside session scope. None = allow. Never raise."""
    _bump("pre_tool_call")
    if session_id:
        _bump("with_session_id")
    if conversation_id:
        _bump("with_conversation_id")
    if not session_id and not conversation_id:
        _bump("with_neither")
    if _breaker_open():
        log.warning("scope-fence: breaker open — fence temporarily disabled")
        return _breaker_open_deny_check(tool_name, args, session_id, conversation_id)
    try:
        result = _pre_tool_call_impl(tool_name, args, session_id, conversation_id)
    except Exception as e:
        return _handle_internal_error(e, tool_name, session_id, conversation_id)
    with _BREAKER_LOCK:
        _BREAKER["errors"] = 0
    return result


def on_post_tool_call(tool_name: str = "", result=None, args=None, session_id: str = "", conversation_id: str = "", **kwargs):
    """Track terminal CWD from result dict/string 'cwd' field or args.workdir. Never raise."""
    _bump("post_tool_call")
    try:
        if tool_name != "terminal":
            return None
        cwd = None
        if isinstance(result, dict):
            cwd = result.get("cwd")
        elif isinstance(result, str):
            try:
                cwd = json.loads(result).get("cwd")
            except (ValueError, TypeError, AttributeError):
                cwd = None
        if not cwd and isinstance(args, dict):
            cwd = args.get("workdir")
        if isinstance(cwd, str) and cwd:
            record_cwd(session_id, cwd, conversation_id)
        return None
    except Exception:
        return None


def on_post_compaction(session_id: str = "", old_session_id: str = "", **kwargs):
    """G1: copy scope + cwd from old_session_id to session_id after compaction."""
    _bump("post_compaction")
    try:
        if not old_session_id or not session_id or old_session_id == session_id:
            return None
        from .store import add_scope
        old_scope = get_scope(old_session_id)
        if old_scope["roots"]:
            add_scope(session_id, [str(r) for r in old_scope["roots"]])
        if old_scope.get("cwd"):
            record_cwd(session_id, old_scope["cwd"])
        invalidate_cache(session_id)
    except Exception:
        pass
    return None


def on_session_reset(session_id: str = "", **kwargs):
    """Cleanup on /new /reset."""
    _bump("session_reset")
    try:
        prune_session(session_id)
    except Exception:
        pass
    _reset_warnings(session_id)
    return None


def on_session_finalize(session_id: str = None, **kwargs):
    """Prune session scope + cwd when session is torn down. Tolerates None."""
    _bump("session_finalize")
    try:
        if session_id:
            prune_session(session_id, kwargs.get("conversation_id", ""))
            _reset_warnings(session_id)
    except Exception:
        pass
    return None
