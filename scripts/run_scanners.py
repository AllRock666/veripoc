#!/usr/bin/env python3
"""Generates real scanner output from OWASP ZAP and ProjectDiscovery Nuclei against the lab.

Saves:
- data/zap_report.json
- data/nuclei.jsonl
"""
import json
import subprocess
import sys
import time
from pathlib import Path
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

ZAP_URL = "http://localhost:8080"
TARGET_ZAP = "http://juiceshop:3000"
TARGET_HOST = "http://localhost:3000"


def run_zap_scan():
    print("=== Step 1: Starting ZAP Spider & Active Scan ===")
    s = requests.Session()

    # 1. Access target via ZAP proxy to populate tree
    print("Populating ZAP tree via target calls...")
    seed_urls = [
        f"{TARGET_ZAP}/",
        f"{TARGET_ZAP}/rest/products/search?q=apple",
        f"{TARGET_ZAP}/rest/user/login",
        f"{TARGET_ZAP}/api/Users",
        f"{TARGET_ZAP}/rest/basket/1",
        f"{TARGET_ZAP}/api/Feedbacks",
        f"{TARGET_ZAP}/profile/image/url",
    ]
    for u in seed_urls:
        try:
            s.get(f"{ZAP_URL}/JSON/core/action/accessUrl/?url={u}", timeout=5)
        except Exception:
            pass

    # 2. Start Spider
    print("Starting ZAP Spider on target...")
    r_spider = s.get(f"{ZAP_URL}/JSON/spider/action/scan/?url={TARGET_ZAP}&maxChildren=10&recurse=true")
    spider_id = r_spider.json().get("scan", "0")
    print(f"Spider started with ID {spider_id}. Waiting for spider to complete...")

    t0 = time.time()
    while time.time() - t0 < 60:
        r_status = s.get(f"{ZAP_URL}/JSON/spider/view/status/?scanId={spider_id}")
        status = int(r_status.json().get("status", 0))
        print(f"  Spider progress: {status}%")
        if status >= 100:
            break
        time.sleep(3)

    # 3. Start Active Scan
    print("Starting ZAP Active Scan on product search and login...")
    ascan_urls = [
        f"{TARGET_ZAP}/rest/products/search?q=1",
        f"{TARGET_ZAP}/rest/user/login",
    ]
    for target_u in ascan_urls:
        r_ascan = s.get(f"{ZAP_URL}/JSON/ascan/action/scan/?url={target_u}&recurse=false")
        ascan_id = r_ascan.json().get("scan", "0")
        print(f"Active scan started on {target_u} with ID {ascan_id}")
        t0 = time.time()
        while time.time() - t0 < 45:
            st = int(s.get(f"{ZAP_URL}/JSON/ascan/view/status/?scanId={ascan_id}").json().get("status", 0))
            print(f"  Active scan progress: {st}%")
            if st >= 100:
                break
            time.sleep(3)

    # 4. Wait for passive scan queue to drain
    print("Waiting for passive scan queue to clear...")
    for _ in range(15):
        pscan_records = int(s.get(f"{ZAP_URL}/JSON/pscan/view/recordsToScan/").json().get("recordsToScan", 0))
        if pscan_records == 0:
            break
        time.sleep(1)

    # 5. Extract JSON report
    print("Exporting traditional ZAP JSON report...")
    r_rep = s.get(f"{ZAP_URL}/OTHER/core/other/jsonreport/")
    rep_json = r_rep.json()
    out_file = DATA_DIR / "zap_report.json"
    out_file.write_text(json.dumps(rep_json, indent=2))
    print(f"ZAP report saved to {out_file} ({out_file.stat().st_size} bytes)")


def run_nuclei_scan():
    print("\n=== Step 2: Running ProjectDiscovery Nuclei ===")
    nuclei_bin = ROOT_DIR / "scripts" / "nuclei.exe"
    targets_file = DATA_DIR / "nuclei_targets.txt"
    targets_file.write_text("\n".join([
        f"{TARGET_HOST}/",
        f"{TARGET_HOST}/#/search?q=apple",
        f"{TARGET_HOST}/rest/products/search?q=apple",
        f"{TARGET_HOST}/rest/user/login",
        f"{TARGET_HOST}/api/Users",
        f"{TARGET_HOST}/rest/basket/1",
        f"{TARGET_HOST}/profile/image/url",
        "http://localhost:4280/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
    ]))

    templates_dir = Path.home() / "nuclei-templates"
    out_file = DATA_DIR / "nuclei.jsonl"

    cmd = [
        str(nuclei_bin),
        "-no-stdin",
        "-l", str(targets_file),
        "-t", str(templates_dir / "dast"),
        "-t", str(templates_dir / "http" / "vulnerabilities"),
        "-t", str(templates_dir / "http" / "misconfiguration"),
        "-t", str(templates_dir / "http" / "exposures"),
        "-t", str(templates_dir / "http" / "technologies"),
        "-jsonl",
        "-o", str(out_file),
        "-silent",
        "-rate-limit", "50",
        "-concurrency", "10",
        "-timeout", "5",
    ]
    print(f"Running Nuclei command: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)
    if out_file.exists():
        print(f"Nuclei output saved to {out_file} ({out_file.stat().st_size} bytes)")
    else:
        out_file.write_text("")
        print(f"Nuclei produced no findings. Created empty {out_file}")


def main():
    run_zap_scan()
    run_nuclei_scan()
    print("\n=== All Scans Complete ===")


if __name__ == "__main__":
    main()
