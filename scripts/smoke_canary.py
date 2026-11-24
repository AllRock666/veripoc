#!/usr/bin/env python3
"""Smoke test 4: Out-of-band canary listener roundtrip verification."""
import json
import sys
import uuid
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from src.sandbox.runner import SandboxRunner


def main():
    print("=== Running Out-of-Band Canary Listener Smoke Test ===")
    token = f"smoke-{uuid.uuid4().hex}"
    print(f"Generated Canary Token: {token}")

    # 1. Reset host canary hits
    try:
        requests.post("http://localhost:9999/_reset", timeout=3)
        print("Reset canary listener log on host (http://localhost:9999/_reset).")
    except Exception as e:
        print(f"[FAIL] Could not reach canary listener on host: {e}")
        sys.exit(1)

    # 2. Run script inside sandbox to trigger canary hit
    script = f"""import requests, json
try:
    r = requests.get("http://canary:9999/{token}", timeout=5)
    print(json.dumps({{"status": r.status_code, "body": r.text}}))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
"""
    runner = SandboxRunner()
    print("Executing probe inside sandbox on lab_net...")
    res = runner.run(script)

    print(f"Sandbox Exit Code: {res.exit_code}")
    print(f"Sandbox Stdout:    {res.stdout.strip()}")
    if res.stderr.strip():
        print(f"Sandbox Stderr:    {res.stderr.strip()}")

    if res.exit_code != 0:
        print("[FAIL] Sandbox script execution failed.")
        sys.exit(1)

    # 3. Verify hit on host
    print("\nQuerying host canary listener (http://localhost:9999/_hits)...")
    try:
        hits_res = requests.get("http://localhost:9999/_hits", timeout=3)
        hits = hits_res.json()
        print(f"Captured hits count: {len(hits)}")
    except Exception as e:
        print(f"[FAIL] Failed to retrieve hits from canary listener: {e}")
        sys.exit(1)

    matched = any(token in h.get("path", "") for h in hits)

    print("\n" + "=" * 65)
    print(f"{'Canary Listener Check':<48} | {'Status':<10}")
    print("=" * 65)
    print(f"{'Canary listener reachable from sandbox':<48} | {'PASS' if 'canary' in res.stdout else 'FAIL':<10}")
    print(f"{'Unique token captured in host /_hits':<48} | {'PASS' if matched else 'FAIL':<10}")
    print("=" * 65)

    if matched:
        print("\n[PASS] Canary listener verified end-to-end.")
        sys.exit(0)
    else:
        print(f"\n[FAIL] Token {token} not found in canary hits: {hits}")
        sys.exit(1)


if __name__ == "__main__":
    main()
