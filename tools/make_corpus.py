"""Convert a user's OWN command log into candidate corpus entries.

Usage:
    python3 tools/make_corpus.py <input> <output>

Input may be plain text (one command per line) or JSONL with a ``command`` field.
Every entry is written with ``expect: "?"`` so the user can dogfood it in ``warn``
mode and report false positives with ``tools/replay.py``.

Redaction (applied before anything is written):
- the current user's home directory is replaced with ``/home/user``;
- other people's home directories (``/home/<name>``, ``/Users/<name>``,
  ``C:\\Users\\<name>``) are rewritten to ``/home/user``;
- lines containing KEY / TOKEN / SECRET / PASSWORD / BEARER / AUTH (case-insensitive)
  are dropped;
- lines with URL credentials (``://user:pass@`` or ``://user@``) are dropped;
- lines with vendor tokens are dropped: ``ghp_``/``gho_``/``ghs_``/``github_pat_``,
  ``glpat-``, ``xox[abp]-``, ``AKIA``, ``AIza``, ``sk-``, and JWTs (``eyJ...``);
- lines longer than 500 characters are dropped.

Redaction is **best-effort**: always review the output file before sharing it.

This tool never assumes a Hermes log format and never writes real logs into the repo.
Stdlib only; no network access.
"""
import argparse
import json
import os
import re

_SECRET_RE = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|BEARER|AUTH", re.IGNORECASE)
# Any credentials in a URL (user:pass@ or user@), not just user:pass@
_URL_CRED_RE = re.compile(r"://[^/\s:@]+(:[^@\s]*)?@")
# Vendor token shapes
_TOKEN_RES = (
    re.compile(r"\b(?:ghp|gho|ghs|github_pat|glpat|xox[abp]|AKIA|AIza)[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\."),  # JWT
)
# Other people's home directories
_HOME_RES = (
    re.compile(r"/home/[A-Za-z0-9._\-]+"),
    re.compile(r"/Users/[A-Za-z0-9._\-]+"),
    re.compile(r"C:\\Users\\[A-Za-z0-9._\-]+"),
)
MAX_LEN = 500


def redact(text, home):
    if home:
        text = text.replace(home, "/home/user")
    for rx in _HOME_RES:
        text = rx.sub("/home/user", text)
    return text


def _looks_secret(cmd):
    if _SECRET_RE.search(cmd) or _URL_CRED_RE.search(cmd):
        return True
    return any(rx.search(cmd) for rx in _TOKEN_RES)


def extract_command(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        if isinstance(obj, dict):
            return obj.get("command") or obj.get("cmd")
        return None
    return line


def convert(text, home):
    entries = []
    for line in text.splitlines():
        cmd = extract_command(line)
        if not cmd or not isinstance(cmd, str):
            continue
        cmd = redact(cmd.strip(), home)
        if not cmd or len(cmd) > MAX_LEN:
            continue
        if _looks_secret(cmd):
            continue
        entries.append({"cmd": cmd, "expect": "?", "tag": "normal",
                        "note": "from user log (synthetic, redacted)"})
    return entries


def main():
    ap = argparse.ArgumentParser(description="Build a candidate scope-fence corpus from a command log.")
    ap.add_argument("input", help="plain text (one command per line) or JSONL with a 'command' field")
    ap.add_argument("output", help="JSONL output path")
    args = ap.parse_args()

    home = os.path.realpath(os.path.expanduser("~"))
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    entries = convert(text, home)

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    print("wrote %d entries -> %s" % (len(entries), args.output))


if __name__ == "__main__":
    main()
