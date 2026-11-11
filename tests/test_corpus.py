"""Replay tests/corpus/commands.jsonl at hook level.

Asserts: zero `tag: mistake` entries are allowed, and the false-positive rate
(`expect: allow` entries that got blocked) is at most 2%.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.environ.get("SCOPE_FENCE_ROOT", os.path.join(os.path.dirname(__file__), "..")))

import scope_fence.store as store_mod

_tmpdir = tempfile.mkdtemp()


_DB_CONN = None


def _init_test_db():
    global _DB_CONN
    if _DB_CONN is not None:
        return _DB_CONN
    import sqlite3
    conn = sqlite3.connect(os.path.join(_tmpdir, "test.db"))
    conn.execute("PRAGMA journal_mode=WAL")
    for t in [
        "scopes (session_id TEXT NOT NULL, path TEXT NOT NULL, added_at REAL NOT NULL, PRIMARY KEY (session_id, path))",
        "cwd_state (session_id TEXT PRIMARY KEY, cwd TEXT, updated_at REAL NOT NULL)",
        "audit (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, ts REAL NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 1, command TEXT)",
        "session_alias (session_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL)",
    ]:
        conn.execute("CREATE TABLE IF NOT EXISTS " + t)
    conn.commit()
    _DB_CONN = conn
    return conn


store_mod._get_db = lambda hermes_home=None: _init_test_db()

import scope_fence.config as cfg_mod
from scope_fence.hooks import on_pre_tool_call
from scope_fence.store import add_scope, invalidate_cache, record_cwd

SCOPE = "/work/proj"
CORPUS = os.path.join(os.path.dirname(__file__), "corpus", "commands.jsonl")


def _load():
    entries = []
    with open(CORPUS) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _verdict(cmd):
    invalidate_cache("corpus")
    add_scope("corpus", [SCOPE])
    record_cwd("corpus", SCOPE)
    invalidate_cache("corpus")
    cfg_mod.set_runtime_config({})
    r = on_pre_tool_call(tool_name="terminal", args={"command": cmd, "workdir": SCOPE},
                         session_id="corpus")
    return r is not None and r.get("action") == "block"


def test_corpus_replay():
    entries = _load()
    assert len(entries) >= 150, f"corpus too small: {len(entries)}"

    allowed_mistakes = []
    false_positives = []
    allow_total = 0
    for e in entries:
        blocked = _verdict(e["cmd"])
        if e["expect"] == "allow":
            allow_total += 1
            if blocked:
                false_positives.append(e)
        elif e["tag"] == "mistake" and not blocked:
            allowed_mistakes.append(e)

    if allowed_mistakes:
        print("ALLOWED MISTAKES:")
        for e in allowed_mistakes:
            print(f"   {e['cmd']}")
    if false_positives:
        print("FALSE POSITIVES:")
        for e in false_positives:
            print(f"   {e['cmd']}")

    fp_rate = (len(false_positives) / allow_total) if allow_total else 0.0
    print(f"corpus: {len(entries)} entries, {allow_total} expect-allow, "
          f"FP={len(false_positives)} ({fp_rate:.2%})")

    assert not allowed_mistakes, f"{len(allowed_mistakes)} mistake entries were allowed"
    assert fp_rate <= 0.02, f"false-positive rate {fp_rate:.2%} > 2%"


if __name__ == "__main__":
    test_corpus_replay()
