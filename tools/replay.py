"""Replay a scope-fence corpus and print entries whose verdict differs from `expect`.

Usage:
    python3 tools/replay.py <corpus.jsonl> [--scope /work/proj] [--cwd /work/proj]

For entries with ``expect: "?"`` every command the fence would block is printed, so a
user can dogfood their own log in ``warn`` mode and report false positives.

Stdlib only; no network access; never raises on a malformed entry.
"""
import argparse
import json
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _install_test_db():
    """Point the store at a throwaway SQLite file (the plugin host is absent here)."""
    import sqlite3
    db_path = os.path.join(tempfile.mkdtemp(), "replay.db")

    def _init():
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS scopes ("
                     "session_id TEXT NOT NULL, path TEXT NOT NULL, added_at REAL NOT NULL, "
                     "PRIMARY KEY (session_id, path))")
        conn.execute("CREATE TABLE IF NOT EXISTS cwd_state ("
                     "session_id TEXT PRIMARY KEY, cwd TEXT, updated_at REAL NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS audit ("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, "
                     "ts REAL NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, "
                     "reason TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 1, command TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS session_alias ("
                     "session_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL)")
        conn.commit()
        return conn

    from scope_fence import store as store_mod
    store_mod._get_db = lambda hermes_home=None: _init()


def _load(path):
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("cmd"), str):
                entries.append(obj)
    return entries


def main():
    ap = argparse.ArgumentParser(description="Replay a scope-fence corpus.")
    ap.add_argument("corpus", help="JSONL with cmd / expect / tag / note")
    ap.add_argument("--scope", default="/work/proj", help="scope root (default /work/proj)")
    ap.add_argument("--cwd", default="/work/proj", help="tracked cwd (default /work/proj)")
    args = ap.parse_args()

    _install_test_db()

    from scope_fence import config as cfg_mod
    from scope_fence.hooks import on_pre_tool_call
    from scope_fence.store import add_scope, invalidate_cache, record_cwd

    entries = _load(args.corpus)
    session = "replay"
    shown = 0
    for e in entries:
        invalidate_cache(session)
        add_scope(session, [args.scope])
        record_cwd(session, args.cwd)
        invalidate_cache(session)
        cfg_mod.set_runtime_config({})
        try:
            r = on_pre_tool_call(tool_name="terminal",
                                 args={"command": e["cmd"], "workdir": args.cwd},
                                 session_id=session)
        except Exception as exc:  # never raise on a malformed entry
            print("[ERROR] %s -> %s" % (e["cmd"], exc))
            continue
        blocked = r is not None and r.get("action") == "block"
        expect = e.get("expect")
        if expect == "?":
            if blocked:
                shown += 1
                print("[BLOCK] %s" % e["cmd"])
        elif (expect == "block") != blocked:
            shown += 1
            got = "block" if blocked else "allow"
            print("[DIFF] expect=%s got=%s :: %s" % (expect, got, e["cmd"]))
    print("---")
    print("%d entries, %d differing/blocked" % (len(entries), shown))


if __name__ == "__main__":
    main()
