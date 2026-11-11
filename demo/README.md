# Demo

## Replay (no model, ten seconds)

```bash
python demo/replay.py
```

Plays the tool calls an agent makes after `cd`-ing into the wrong checkout, through
scope-fence's hooks exactly as Hermes calls them, and prints each decision. No Hermes
install, no network, nothing is written to your machine: the checkouts live in a
temporary directory.

The scenario covers:

1. ordinary work inside the scope
2. the honest mistake — the wrong checkout
3. scratch paths and the deny-list
4. shell tricks (`bash -i -c`, `env`, `$(...)`, compact `-o/path`, `find -exec`)
5. read-only commands that are *not* blocked
6. `warn` mode — the same call, recorded but not blocked
7. widening the scope with `/scope add`, and the call passing

## Live, with your own Hermes

1. Create two checkouts:
   ```bash
   mkdir -p ~/scope-fence-demo/project-a ~/scope-fence-demo/project-b
   cd ~/scope-fence-demo/project-a && git init -q
   cd ~/scope-fence-demo/project-b && git init -q
   ```
2. In a Hermes session with scope-fence enabled:
   ```
   /scope add ~/scope-fence-demo/project-a
   ```
3. Ask the agent: *"clean the build directory in project-b"*
4. Watch the agent's `cd ~/scope-fence-demo/project-b && rm -rf build` get blocked.
   `/scope check` shows the reason (`outside-scope`).
5. Widen the scope: `/scope add "~/scope-fence-demo/project-b"` — the same call now passes.
6. Cleanup: `rm -rf ~/scope-fence-demo`

> Use `$HOME`, not `/tmp`: `/tmp` is a writable scratch path by default, so a block would
> not trigger there.

## What the output means

| Line | Meaning |
|---|---|
| `allowed` | the call passes the fence |
| `⛔ Scope Fence blocked this call.` | the call is refused before it runs |
| `Reason: target is on the deny-list.` | the deny-list wins over everything, including scope and scratch |
| `Reason: write outside the declared scope.` | the target resolves outside every scope root |

The block message always ends with a recovery line: do not retry or work around it —
ask the user to run `/scope add <dir>`, or continue inside the scope.
