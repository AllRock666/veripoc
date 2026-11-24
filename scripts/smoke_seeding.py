#!/usr/bin/env python3
"""Smoke test 3: Lab seeding and IDOR access control verification."""
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from lab.seed import seed_juice_shop, DEFAULT_CANARY


def main():
    print("=== Running Lab Seeding Smoke Test ===")
    canary = DEFAULT_CANARY
    target = "http://localhost:3000"

    print(f"Target: {target}")
    print(f"Canary: {canary}")

    # 1. Run seed script
    try:
        creds = seed_juice_shop(target_url=target, canary_value=canary)
        print("\n[OK] Lab seeding executed successfully.")
    except Exception as e:
        print(f"[FAIL] Lab seeding failed: {e}")
        sys.exit(1)

    token_a = creds["user_a"]["token"]
    token_b = creds["user_b"]["token"]
    bid_b = creds["user_b"]["bid"]
    addr_id_b = creds["user_b"].get("address_id")

    print(f"User A Token: {token_a[:15]}... Basket: {creds['user_a']['bid']}")
    print(f"User B Token: {token_b[:15]}... Basket: {bid_b} Address ID: {addr_id_b}")

    s = requests.Session()

    # 2. Verify User B can read own canary in addresses
    print("\nVerifying User B access to own Address...")
    res_b_addr = s.get(f"{target}/api/Addresss", headers={"Authorization": f"Bearer {token_b}"})
    user_b_reads_canary = (res_b_addr.status_code == 200 and canary in res_b_addr.text)
    print(f"User B -> /api/Addresss status: {res_b_addr.status_code}, canary present: {canary in res_b_addr.text}")

    # 3. Test User A access to User B's address
    print("\nTesting User A access to User B's Address (/api/Addresss)...")
    res_a_addr = s.get(f"{target}/api/Addresss", headers={"Authorization": f"Bearer {token_a}"})
    print(f"User A -> /api/Addresss status: {res_a_addr.status_code}, canary present: {canary in res_a_addr.text}")

    if addr_id_b:
        print(f"Testing User A access to User B's specific Address (/api/Addresss/{addr_id_b})...")
        res_a_spec_addr = s.get(f"{target}/api/Addresss/{addr_id_b}", headers={"Authorization": f"Bearer {token_a}"})
        print(f"User A -> /api/Addresss/{addr_id_b} status: {res_a_spec_addr.status_code}, body: {res_a_spec_addr.text[:200]}")

    # 4. Test User A access to User B's basket (/rest/basket/{bid_b})
    print(f"\nTesting User A access to User B's Basket (/rest/basket/{bid_b})...")
    res_a_basket = s.get(f"{target}/rest/basket/{bid_b}", headers={"Authorization": f"Bearer {token_a}"})
    user_a_reads_basket_canary = (res_a_basket.status_code == 200 and canary in res_a_basket.text)
    print(f"User A -> /rest/basket/{bid_b} status: {res_a_basket.status_code}, canary present: {user_a_reads_basket_canary}")

    # Summary table
    print("\n" + "=" * 65)
    print(f"{'Access Control / Seeding Check':<48} | {'Status':<10}")
    print("=" * 65)
    print(f"{'User B reads own Address canary (/api/Addresss)':<48} | {'PASS' if user_b_reads_canary else 'FAIL':<10}")
    print(f"{'User A blocked from User B Address (/api/Addresss)':<48} | {'PASS' if canary not in res_a_addr.text else 'FAIL':<10}")
    print(f"{'User A reads User B Basket canary (/rest/basket)':<48} | {'PASS' if user_a_reads_basket_canary else 'FAIL':<10}")
    print("=" * 65)

    if user_b_reads_canary and user_a_reads_basket_canary:
        print("\n[PASS] Seeding and access control verification complete.")
        sys.exit(0)
    else:
        print("\n[FAIL] Seeding verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
