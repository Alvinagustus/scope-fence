# Scope Fence

A per-session directory write guardrail for [Hermes Agent](https://hermes-agent.nousresearch.com).
Declare a scope with `/scope`; the fence blocks file writes and destructive terminal commands
that resolve outside it.

## The problem

An agent that writes files and runs terminal commands has no enforced boundary on
*where* it is allowed to work. Approvals are per command, and an agent can misjudge
which directory it is in — a wrong checkout, a `cd` that did not take, a relative
path that resolves elsewhere. A single mistake can then destroy work that cannot
be recovered. This is not hypothetical; it has happened repeatedly:

- **Claude Code issue #53196 (25 Apr 2026).** The Bash working directory silently
  reverted to a previous directory. The agent ran `git commit --amend`, rewriting
  an already-merged public commit, then `git reset --hard`, deleting a week of
  staged work. Recovery only succeeded because a dangling commit happened to
  exist — and the agent had ignored the `reset --hard` ban in its own CLAUDE.md.
- **Wrong checkout (13 Mar, reported on popularai.org).** An agent ran
  `git reset --hard origin/main` in the wrong checkout and deleted about two days
  of uncommitted changes. Recovery failed.
- **October 2026 deletion cluster (reported incidents).** 116 GB deleted through
  a Windows 8.3 short-name alias; a whole drive C deleted by an agent asked to
  clean a subfolder. See the public trackers for the full list.

Scope Fence is the boundary these incidents lacked: declare the directories the
agent may touch, and the fence blocks writes and destructive commands outside
them — enforced by code in `pre_tool_call`, not by a prompt the agent can ignore.

## What this is / is not

**It is** a guardrail against honest agent mistakes: the wrong checkout, a wrong `cd`, a wrong
relative path, `rm` / `mv` / `git reset` aimed at the wrong directory, or writing a skill or
config file it should not touch.

**It is not a security boundary.** It does not stop deliberate evasion, prompt injection, or code
that writes files indirectly (process substitution, `$'..'` quoting, `chr()`-built paths,
scripts that write elsewhere). For real isolation use bubblewrap, containers or VMs. The two
combine well: Scope Fence catches the honest mistake, the sandbox catches everything else.

It parses POSIX shell syntax (`sh`, `bash`, `zsh`, `dash`, `ksh`). PowerShell and cmd.exe are not modelled.

## Requirements

- Hermes Agent `>= 0.22.6`
- Python `>= 3.9`, standard library only (no network, no extra dependencies)

## Install

```bash
hermes plugins install scope-fence      # once listed in the catalog
hermes plugins enable scope-fence
```

Until it is listed, install from the repository: `hermes plugins install Alvinagustus/scope-fence`.

## Quickstart

1. Enable the plugin.
2. Start in **`warn` mode** (recommended for the first week). It records what it *would* block
   but stops nothing, except deny-listed paths:
   ```yaml
   plugins:
     entries:
       scope-fence:
         settings:
           mode: warn
   ```
3. Work normally. The fence auto-scopes to your project's git root on the first write, and
   scratch directories (`/tmp`, `$TMPDIR`, `~/.cache`) are writable out of the box.
4. Review what it caught with `/scope check`.
5. When you trust it, set `mode: enforce`.
6. If anything looks off, run `/scope doctor`.

## Commands

```
/scope add <dir> [<dir> ...]    add scope roots (up to max_scope_paths)
/scope list                     show scope roots and scratch paths
/scope remove <dir>             remove a scope root
/scope check                    recent audit entries, mode, summary
/scope doctor                   self-diagnosis: one OK / WARN / FAIL line per check
```

## How it works

| Part | Behaviour |
|---|---|
| Auto-scope | With no scope declared, the git root of the session CWD (`git rev-parse --show-toplevel`) becomes the scope. Falls back to the process CWD on the first call. Never auto-scopes to a filesystem root or `$HOME`. A failed attempt is retried after 60 seconds. |
| `pre_tool_call` | Checks `write_file`, `patch`, `skill_manage` writes and `terminal` commands. Wrapper commands (`env`, `sudo`, `nohup`, `eval`, ...) are unwrapped before classification. |
| Patch headers | `patch` targets are read from the V4A headers Hermes itself parses: `*** Add File:`, `*** Update File:`, `*** Delete File:` and `*** Move File: a -> b` (both sides checked). Hermes does not accept a standard unified diff (`--- a/` / `+++ b/`), so that form is not parsed. |
| Deny-list | `~/.ssh`, `~/.env`, `~/.aws`, `~/.gnupg`, `~/.config`, shell rc files and `~/.hermes` are never writable: inside scope, with no scope, in both modes, and while the circuit breaker is open. |
| Scratch paths | `/tmp`, `$TMPDIR` and `~/.cache` count as writable so build output and caches are not interrupted. The deny-list wins over them. |
| Path resolution | Symlinks and `..` are resolved with `realpath` before comparison. Relative paths resolve against the session CWD, not the process CWD. A POSIX-style absolute path (`/outside/x`) counts as absolute on every platform, matching the shell. |
| CWD tracking | The terminal CWD is tracked via `post_tool_call`. A `cd` into a non-literal target (`$VAR`, glob) marks the CWD unknown, and later writers with relative operands are blocked. |
| Audit log | Every block and every `warn`-mode would-block is recorded (tool, resolved path, reason; never the raw command). View it with `/scope check`. Cleared when the session ends. |
| Compaction | `post_compaction` copies scope and CWD to the new session id, so the fence survives context compaction. |
| Circuit breaker | Three consecutive internal errors open the fence for 60 seconds instead of blocking every call. The deny-list still applies. |

## Modes

| Mode | Behaviour |
|---|---|
| `enforce` (default) | Blocks scope, unparseable, strict-mode and `deny_by_default` violations. |
| `warn` | Lets those calls through, records `would-block:<reason>` in the audit log, and logs a warning. |

The deny-list is enforced in both modes.

## Configuration

Settings live under `plugins.entries.scope-fence.settings` in `~/.hermes/config.yaml`:

```yaml
plugins:
  entries:
    scope-fence:
      settings:
        mode: enforce                 # enforce | warn
        deny_paths: ["~/.ssh", "~/.env", "~/.aws", "~/.gnupg", "~/.config", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.hermes"]
        replace_default_deny: false   # true: deny_paths replaces the defaults
        extra_write_paths: ["/tmp", "$TMPDIR", "~/.cache"]
        replace_default_extra_write_paths: false  # true: extra_write_paths replaces the defaults
        block_unparseable_destructive: true
        allow_reads_outside_scope: true
        allow_skill_writes: false     # true: skill_manage skips the scope check (deny-list still applies)
        max_scope_paths: 8
        auto_scope: true
        deny_by_default: false        # true: block all writes when no scope is declared
        strict_mode: false            # true: block destructive commands even inside scope
```

- `deny_paths` extends the defaults unless `replace_default_deny` is true.
- `extra_write_paths` extends the defaults unless `replace_default_extra_write_paths` is true. Filesystem roots and `$HOME` itself are rejected.
- Only the `plugins.entries.scope-fence.settings` section is read.

`~/.hermes` and `~/.config` are denied, so the agent cannot write its own skills or memory with
`write_file` / `patch`. Use `skill_manage` instead: it is a Hermes-mediated, name-validated write,
so a deny entry that **covers the skills directory** does not apply to it (a raw `write_file` /
`patch` to the same path stays blocked), but the scope check does. Set `allow_skill_writes: true`
to skip that scope check.

## FAQ

**Why was my command blocked?**
Run `/scope check`. It lists the tool, the resolved target and the reason (`deny-list`,
`outside-scope`, `unparseable`, `strict-mode`, `deny_by_default`). Deny-list entries cannot be disabled.

**How do I widen the scope?**
`/scope add <dir>`. Scratch directories are always writable and shown under "Scratch paths".

**My path has a space in it (`C:\Users\Alvin Agustus\project`).**
Quote it: `/scope add "C:\Users\Alvin Agustus\project"`. Arguments are parsed like a shell
command line, so an unquoted space splits one path into several arguments.

**Why can't I write to `~/.hermes`?**
It is on the default deny-list. Use `skill_manage` for skills, or set `allow_skill_writes: true`.

**How do I check it works?**
`/scope doctor` prints one line per check (session context, database roundtrip, effective
config, hook counters, breaker state, scope and CWD), each `OK`, `WARN` or `FAIL`.

## What it does not cover

- **Tool calls from inside `execute_code` scripts.** Their session ids can be empty, so the fence is inactive for them.
- **Callers that skip the `pre_tool_call` hook** or dispatch straight through the registry.
- **Files written by scripts, interpreters and build tools** (`python3 script.py`, `node app.js`, `npm run build`). Visible path operands are checked; interpreter code is not analysed.
- **Deliberate obfuscation**: process substitution, ANSI-C quoting, brace expansion, dynamically built paths, encoded payloads.
- **Subagent hook propagation**: not verified against a live Hermes build.
- **Deletions already running in the background.**

## Known limitations

- **Shell parsing** covers multi-segment commands (`&&`, `||`, `;`, `|`, newline, `&`), `cd` / `pushd` / `git -C`, `sh -c` unwrapping, wrapper stripping, `xargs` and `find -exec`, redirection targets, `--flag=value`, `dd if=/of=`, and `$(...)` / backtick substitutions that contain a destructive command.
- **Piping into a shell, and `xargs` with a destructive command**: blocked as unverifiable, because the piped content cannot be checked. Read-only pipelines pass.
- **Repo-state git commands** (`git branch -D`, `git remote remove`, `git stash`, `git apply`, `git config`) change repository state rather than files and are blocked.
- **Destructive commands inside scope pass**: the fence is a boundary, not a safety rating. `git reset --hard` in the correct checkout is allowed; enable `strict_mode` to block it.
- **No scope declared**: if auto-scope fails and no scope is set, the fence is inactive unless `deny_by_default: true`. The deny-list still applies.
- **Windows**: 8.3 short names are not expanded.

## Security and privacy

- **Shell command**: auto-scope runs `git rev-parse --show-toplevel` locally, read-only, with a 5 s timeout. No network, no LLM.
- **Reads**: agent-supplied paths are resolved with `realpath` for comparison. File contents are never opened.
- **Stored state** (Hermes `plugin_db`, local SQLite): scope roots, tracked CWD, and audit entries (tool name, resolved path, reason). Cleared when the session ends. Never file contents, command output or raw commands.
- **Deny-list paths** are used only as strings for comparison; they are never opened or read.
- **Credentials**: none are read. Configuration comes only through `ctx.get_config()`.
- **Approvals**: untouched. The plugin blocks before approval is reached.
- **Telemetry and network**: none.

## Files

```
plugin.yaml               manifest
__init__.py               register(ctx): hooks, /scope command, system-prompt section
scope_fence/__init__.py   package root
scope_fence/config.py     defaults, validation, scratch paths
scope_fence/paths.py      realpath resolution, scope and deny-list checks
scope_fence/terminal.py   multi-segment shell command classifier
scope_fence/store.py      plugin_db schema, cache, audit log
scope_fence/hooks.py      hooks, warn/enforce, circuit breaker, counters
scope_fence/commands.py   /scope add | list | remove | check | doctor
tests/                    pytest suite + command corpus
tools/                    corpus builder and replay helper (development only)
demo/                     replay.py — the demo scenario, no model, no Hermes install
.github/workflows/        CI: pytest matrix (3.9-3.13) + Windows + runtime test
LICENSE                   MIT
```

## License

MIT
