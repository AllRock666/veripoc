#!/usr/bin/env python3
"""Smoke test 1: Start lab containers and verify their health."""
import subprocess
import sys
import time
import requests


def check_endpoint(name: str, url: str, expected_codes=(200,), max_retries=15, delay=2) -> bool:
    print(f"Waiting for {name} at {url}...", end="", flush=True)
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in expected_codes:
                print(f" READY (status {r.status_code})")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(delay)
    print(" FAILED")
    return False


def main():
    print("=== Starting Lab Containers ===")
    res = subprocess.run(["docker", "compose", "-f", "lab/docker-compose.yml", "up", "-d", "--build"], check=False)
    if res.returncode != 0:
        print("ERROR: Failed to start docker compose lab.")
        sys.exit(1)

    print("\n=== Verifying Lab Service Endpoints ===")
    services = [
        ("OWASP Juice Shop", "http://localhost:3000", (200,)),
        ("DVWA", "http://localhost:4280/login.php", (200, 302)),
        ("Canary Listener", "http://localhost:9999/_hits", (200,)),
    ]

    all_ok = True
    for name, url, codes in services:
        if not check_endpoint(name, url, codes):
            all_ok = False

    if all_ok:
        print("\n[PASS] All lab services are healthy and responding.")
        sys.exit(0)
    else:
        print("\n[FAIL] One or more lab services failed health check.")
        sys.exit(1)


if __name__ == "__main__":
    main()
