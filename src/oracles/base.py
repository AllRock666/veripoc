"""Deterministic oracles. The LLM never decides the verdict; code does.

Telemetry contract: the generated script prints ONE final JSON line to stdout, e.g.
  SQLi : {"completed":true,"baseline_ms":[..],"payload_ms":[..],"delay_s":3,"body":"..."}
  XSS  : {"completed":true,"xss_fired":true|false}
  SSRF : {"completed":true,"token":"<uuid>"}            (oracle checks canary hits)
  IDOR : {"completed":true,"status":200,"body":"..."}   (oracle checks canary data)
`completed` means the test ran its full procedure (not crashed / auth-failed)."""
from dataclasses import dataclass, field
from ..ingestion.schema import Finding, Verdict, VulnClass


@dataclass
class OracleContext:
    canary_value: str = ""
    canary_hits: list = field(default_factory=list)


@dataclass
class OracleResult:
    verdict: Verdict
    reason: str


def _incomplete(t): return not t.get("completed")


def sqli_oracle(f, t, ctx) -> OracleResult:
    if _incomplete(t):
        return OracleResult(Verdict.INCONCLUSIVE, "test did not complete")
    if ctx.canary_value and ctx.canary_value in str(t.get("body", "")):
        return OracleResult(Verdict.CONFIRMED, "seeded canary extracted via injection")
    base, pay = t.get("baseline_ms") or [], t.get("payload_ms") or []
    delay = float(t.get("delay_s", 0)) * 1000
    if len(base) >= 2 and len(pay) >= 2 and delay > 0:
        b = max(base)
        if all(p - b >= 0.8 * delay for p in pay):
            return OracleResult(Verdict.CONFIRMED, f"payload consistently slower by >= {0.8*delay:.0f}ms")
        return OracleResult(Verdict.FALSE_POSITIVE, "no timing delta across repeated trials")
    if ctx.canary_value and "body" in t:
        return OracleResult(Verdict.FALSE_POSITIVE, "seeded canary not extracted")
    return OracleResult(Verdict.INCONCLUSIVE, "insufficient timing samples")


def xss_oracle(f, t, ctx) -> OracleResult:
    if _incomplete(t):
        return OracleResult(Verdict.INCONCLUSIVE, "test did not complete")
    if t.get("xss_fired") is True:
        return OracleResult(Verdict.CONFIRMED, "JS execution observed in headless browser")
    return OracleResult(Verdict.FALSE_POSITIVE, "no JS execution (reflection alone is not XSS)")


def ssrf_oracle(f, t, ctx) -> OracleResult:
    if _incomplete(t) or not t.get("token"):
        return OracleResult(Verdict.INCONCLUSIVE, "no token / test incomplete")
    if any(t["token"] in h.get("path", "") for h in ctx.canary_hits):
        return OracleResult(Verdict.CONFIRMED, "target issued inbound request to canary with unique token")
    return OracleResult(Verdict.FALSE_POSITIVE, "no callback received")


def idor_oracle(f, t, ctx) -> OracleResult:
    if _incomplete(t):
        return OracleResult(Verdict.INCONCLUSIVE, "test did not complete")
    if t.get("status") == 200 and ctx.canary_value and ctx.canary_value in str(t.get("body", "")):
        return OracleResult(Verdict.CONFIRMED, "User A read User B's canary data")
    return OracleResult(Verdict.FALSE_POSITIVE, "access denied or canary absent")


ORACLES = {VulnClass.SQLI: sqli_oracle, VulnClass.XSS: xss_oracle,
           VulnClass.SSRF: ssrf_oracle, VulnClass.IDOR: idor_oracle}


def evaluate(f: Finding, telemetry: dict, ctx: OracleContext) -> OracleResult:
    fn = ORACLES.get(f.vuln_class)
    if not fn:
        return OracleResult(Verdict.INCONCLUSIVE, f"no oracle for {f.vuln_class.value}")
    return fn(f, telemetry, ctx)
