#!/usr/bin/env python3
"""Smoke test 2: Sandbox isolation and volume mount verification."""
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.sandbox.runner import SandboxRunner

TEST_SCRIPT = """import json
import os
import sys
import requests

results = {}

# (a) Reach internal target
try:
    r = requests.get("http://juiceshop:3000", timeout=5)
    results["reach_juiceshop"] = (r.status_code == 200)
except Exception as e:
    results["reach_juiceshop"] = False
    results["reach_juiceshop_err"] = str(e)

# (b) Block external egress
try:
    requests.get("https://example.com", timeout=3)
    results["no_egress"] = False  # Should NOT succeed
except Exception:
    results["no_egress"] = True   # Connection failed as expected

# (c) Read-only filesystem outside /tmp
write_blocked = False
try:
    with open("/work/test_write.txt", "w") as f:
        f.write("fail")
except OSError:
    write_blocked = True
except Exception:
    write_blocked = True

# Can write inside /tmp
tmp_writable = False
try:
    with open("/tmp/probe.txt", "w") as f:
        f.write("ok")
    with open("/tmp/probe.txt", "r") as f:
        tmp_writable = (f.read() == "ok")
except Exception:
    tmp_writable = False

results["read_only_fs"] = (write_blocked and tmp_writable)

# (d) Non-root execution
uid = os.getuid() if hasattr(os, "getuid") else -1
results["non_root"] = (uid != 0)
results["uid"] = uid

# (e) Volume mount
results["work_mount_ok"] = os.path.exists("/work/test.py")

print(json.dumps(results))
"""


def main():
    print("=== Running Sandbox Isolation Test ===")
    runner = SandboxRunner()
    res = runner.run(TEST_SCRIPT)

    print(f"Container Exit Code: {res.exit_code}")
    print(f"Container Duration:  {res.duration_s:.2f}s")
    if res.stderr.strip():
        print(f"Container Stderr:    {res.stderr.strip()}")

    if res.exit_code != 0:
        print("[FAIL] Sandbox execution failed.")
        sys.exit(1)

    try:
        data = json.loads(res.stdout.strip().splitlines()[-1])
    except Exception as e:
        print(f"[FAIL] Could not parse container output: {res.stdout} ({e})")
        sys.exit(1)

    checks = [
        ("(a) Target Reachability (http://juiceshop:3000)", data.get("reach_juiceshop") is True),
        ("(b) Internet Egress Blocked (https://example.com)", data.get("no_egress") is True),
        ("(c) Read-Only Filesystem (only /tmp writable)", data.get("read_only_fs") is True),
        (f"(d) Non-Root User (UID={data.get('uid')})", data.get("non_root") is True),
        ("(e) Volume Mount (/work/test.py readable)", data.get("work_mount_ok") is True),
    ]

    print("\n" + "=" * 65)
    print(f"{'Security Control / Check':<48} | {'Status':<10}")
    print("=" * 65)
    all_passed = True
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"{label:<48} | {status:<10}")
    print("=" * 65)

    if all_passed:
        print("\n[PASS] All sandbox isolation controls verified successfully.")
        sys.exit(0)
    else:
        print("\n[FAIL] One or more sandbox isolation controls failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
