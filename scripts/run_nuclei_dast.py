#!/usr/bin/env python3
"""Runs targeted Nuclei DAST scans against Juice Shop and DVWA endpoints."""
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
NUCLEI = ROOT_DIR / "scripts" / "nuclei.exe"
TEMPLATES = Path.home() / "nuclei-templates"
OUT_FILE = DATA_DIR / "nuclei.jsonl"

targets = [
    "http://127.0.0.1:3000/rest/products/search?q=1",
    "http://127.0.0.1:3000/rest/user/login",
    "http://127.0.0.1:3000/api/Users",
    "http://127.0.0.1:3000/rest/basket/1",
    "http://127.0.0.1:3000/profile/image/url",
    "http://127.0.0.1:4280/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
]
targets_path = DATA_DIR / "nuclei_targets.txt"
targets_path.write_text("\n".join(targets))

cmd = [
    str(NUCLEI),
    "-no-stdin",
    "-l", str(targets_path),
    "-t", str(TEMPLATES / "dast" / "vulnerabilities" / "sqli"),
    "-t", str(TEMPLATES / "dast" / "vulnerabilities" / "xss"),
    "-t", str(TEMPLATES / "dast" / "vulnerabilities" / "ssrf"),
    "-t", str(TEMPLATES / "http" / "misconfiguration"),
    "-dast",
    "-jsonl",
    "-o", str(OUT_FILE),
    "-silent",
    "-rate-limit", "30",
    "-timeout", "5",
]

print("Running command:", " ".join(cmd))
res = subprocess.run(cmd, check=False)
print("Exit code:", res.returncode)
if OUT_FILE.exists():
    lines = [l for l in OUT_FILE.read_text().splitlines() if l.strip()]
    print(f"Nuclei produced {len(lines)} JSONL finding(s).")
