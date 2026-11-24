#!/usr/bin/env python3
"""Seeds OWASP Juice Shop with two users and a canary record for User B.

Ground truth setup for:
- IDOR (CWE-639): User A accesses User B's basket or address containing the canary string.
- SQLi (CWE-89): Union-based injection extracting User B's canary record from the database.
"""
from __future__ import annotations
import argparse
import json
import sys
import requests

DEFAULT_CANARY = "CANARY_JuiceShop_UserB_Secret_Record_83f9"


def seed_juice_shop(
    target_url: str = "http://localhost:3000",
    canary_value: str = DEFAULT_CANARY,
    user_a_email: str = "usera@pocverifier.local",
    user_b_email: str = "userb@pocverifier.local",
    password: str = "PocVerifier!Pass123",
    seed_state_path: str | None = None,
) -> dict:
    target = target_url.rstrip("/")
    s = requests.Session()

    # 1. Fetch available security questions (with retry if starting up)
    sq_id = 1
    for _ in range(10):
        try:
            sq_res = s.get(f"{target}/api/SecurityQuestions", timeout=5)
            if sq_res.status_code == 200:
                sq_data = sq_res.json().get("data", [])
                if sq_data:
                    sq_id = sq_data[0]["id"]
                break
        except Exception:
            import time
            time.sleep(1)

    # 2. Register users if not existing
    for email, ans in [(user_a_email, "AnswerA"), (user_b_email, canary_value)]:
        payload = {
            "email": email,
            "password": password,
            "securityQuestion": {"id": sq_id},
            "securityAnswer": ans,
        }
        try:
            s.post(f"{target}/api/Users", json=payload, timeout=5)
        except Exception:
            pass

    # 3. Log in User A
    login_a = s.post(f"{target}/rest/user/login", json={"email": user_a_email, "password": password}, timeout=5)
    login_a.raise_for_status()
    auth_a = login_a.json().get("authentication", {})
    token_a = auth_a.get("token", "")
    bid_a = auth_a.get("bid", 1)

    # 4. Log in User B
    login_b = s.post(f"{target}/rest/user/login", json={"email": user_b_email, "password": password}, timeout=5)
    login_b.raise_for_status()
    auth_b = login_b.json().get("authentication", {})
    token_b = auth_b.get("token", "")
    bid_b = auth_b.get("bid", 2)

    # 5. Seed canary record for User B in Addresss
    address_id = None
    if token_b:
        addr_res = s.post(
            f"{target}/api/Addresss",
            headers={"Authorization": f"Bearer {token_b}"},
            json={
                "country": "Canaryland",
                "fullName": f"User B Canary ({canary_value})",
                "mobileNum": 9999999999,
                "zipCode": "99999",
                "streetAddress": canary_value,
                "city": "CanaryCity",
            },
            timeout=5,
        )
        if addr_res.status_code in (200, 201):
            address_id = addr_res.json().get("data", {}).get("id")

        # Also add an item to User B's basket so /rest/basket/{bid_b} has items
        try:
            s.post(
                f"{target}/api/BasketItems",
                headers={"Authorization": f"Bearer {token_b}"},
                json={"ProductId": 2, "BasketId": str(bid_b), "quantity": 1},
                timeout=5,
            )
        except Exception:
            pass

        # Seed canary directly into User B's basket coupon in DB if accessible via docker
        try:
            import subprocess
            subprocess.run([
                "docker", "exec", "juiceshop",
                "/nodejs/bin/node", "-e",
                f"const sqlite3 = require('sqlite3'); const db = new sqlite3.Database('data/juiceshop.sqlite'); db.run('UPDATE Baskets SET coupon=? WHERE id=?', ['{canary_value}', {bid_b}]);"
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    result = {
        "target": target,
        "canary_value": canary_value,
        "user_a": {
            "email": user_a_email,
            "password": password,
            "token": token_a,
            "bid": bid_a,
        },
        "user_b": {
            "email": user_b_email,
            "password": password,
            "token": token_b,
            "bid": bid_b,
            "address_id": address_id,
        },
    }

    if seed_state_path:
        try:
            from pathlib import Path
            seed_state = {
                "victim_basket_id": str(bid_b),
                "victim_address_id": str(address_id) if address_id is not None else "",
            }
            Path(seed_state_path).write_text(json.dumps(seed_state, indent=2))
        except Exception:
            pass

    return result


def seed_dvwa(dvwa_url: str = "http://localhost:4280") -> bool:
    """Initializes DVWA database via setup.php and sets default security to low."""
    import re, time
    target = dvwa_url.rstrip("/")
    s = requests.Session()
    # Retry waiting for DVWA to be up
    for _ in range(15):
        try:
            r = s.get(f"{target}/setup.php", timeout=5)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(1)

    try:
        r_setup = s.get(f"{target}/setup.php", timeout=5)
        m = re.search(r"value='([a-f0-9]+)'", r_setup.text)
        if m:
            s.post(f"{target}/setup.php", data={
                "create_db": "Create / Reset Database",
                "user_token": m.group(1),
            }, timeout=10)

        # Login admin / password
        r_login_page = s.get(f"{target}/login.php", timeout=5)
        m_login = re.search(r"value='([a-f0-9]+)'", r_login_page.text)
        if m_login:
            s.post(f"{target}/login.php", data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": m_login.group(1),
            }, timeout=5)

        # Set security level to low
        r_sec_page = s.get(f"{target}/security.php", timeout=5)
        m_sec = re.search(r"value='([a-f0-9]+)'", r_sec_page.text)
        if m_sec:
            s.post(f"{target}/security.php", data={
                "security": "low",
                "seclev_submit": "Submit",
                "user_token": m_sec.group(1),
            }, timeout=5)
        return True
    except Exception as e:
        print(f"Warning: Failed to setup DVWA: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Seed OWASP Juice Shop and DVWA with test users and canary data")
    parser.add_argument("--target", default="http://localhost:3000", help="Target Juice Shop base URL")
    parser.add_argument("--dvwa", default="http://localhost:4280", help="Target DVWA base URL")
    parser.add_argument("--canary", default=DEFAULT_CANARY, help="Canary string to seed into User B record")
    parser.add_argument("--out", default="lab/credentials.json", help="Optional JSON file path to write credentials to")
    parser.add_argument("--seed-state", default="lab/seed_state.json", help="JSON file path to write victim IDs to")
    args = parser.parse_args()

    try:
        res = seed_juice_shop(args.target, args.canary, seed_state_path=args.seed_state)
        seed_dvwa(args.dvwa)
        out_json = json.dumps(res, indent=2)
        print(out_json)
        if args.out:
            with open(args.out, "w") as f:
                f.write(out_json)
            print(f"Credentials written to {args.out}", file=sys.stderr)
        if args.seed_state:
            print(f"Seed state written to {args.seed_state}", file=sys.stderr)
    except Exception as e:
        print(f"Error seeding lab: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
