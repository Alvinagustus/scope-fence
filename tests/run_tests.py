"""Run the whole scope-fence suite and write a single report.

Usage (from anywhere):
    python run_tests.py

Runs:
  1. the unit + Windows path tests  (python -m pytest -q -rs)
  2. the runtime test through Hermes's own PluginManager (runtime_test_full.py)

Writes HASIL-TEST.txt next to this file. A runtime-test SKIP (no Hermes source and no
importable hermes_cli) is reported but does not fail the run.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYTHON = sys.executable


def run(label, *cmd):
    print(f"\n{'=' * 70}\n=== {label}\n{'=' * 70}")
    try:
        proc = subprocess.run([str(c) for c in cmd], cwd=str(HERE),
                              capture_output=True, text=True, errors="replace")
    except Exception as e:
        print(f"could not run: {e}")
        return 1, f"could not run: {e}"
    output = (proc.stdout or "") + (proc.stderr or "")
    print(output.rstrip())
    if "No module named pytest" in output:
        print("-> pytest is not installed for this Python. Run: "
              f"{PYTHON} -m pip install pytest")
    skipped = "SKIP:" in output
    ok = proc.returncode == 0 or skipped
    return (0 if ok else 1), output


def main():
    print("scope-fence test runner")
    print("python:", PYTHON)
    print("tests: ", HERE)

    report = [f"python: {PYTHON}", f"tests: {HERE}", ""]

    rc1, out1 = run("1. unit + Windows tests", PYTHON, "-m", "pytest", "-q", "-rs")
    report.append(f"\n{'=' * 70}\n=== 1. unit + Windows tests (exit {rc1}) ===\n{'=' * 70}")
    report.append(out1)

    rc2, out2 = run("2. runtime test (Hermes PluginManager)", PYTHON, "runtime_test_full.py")
    report.append(f"\n{'=' * 70}\n=== 2. runtime test (exit {rc2}) ===\n{'=' * 70}")
    report.append(out2)

    out = HERE / "HASIL-TEST.txt"
    out.write_text("\n".join(report), encoding="utf-8")

    print(f"\n{'=' * 70}")
    print(f"unit+windows : {'OK' if rc1 == 0 else 'FAIL'}")
    print(f"runtime      : {'OK (or SKIP)' if rc2 == 0 else 'FAIL'}")
    print(f"report -> {out}")
    return 0 if (rc1 == 0 and rc2 == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
