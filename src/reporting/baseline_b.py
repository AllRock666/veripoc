"""Baseline B: Zero-shot LLM triage of raw scanner alerts with NO sandbox execution."""
from __future__ import annotations
import json
import re
from typing import Any
from ..ingestion.schema import Finding, Verdict

TRIAGE_SYSTEM = """You are an AppSec vulnerability triage expert.
Analyze the given automated scanner alert, including target URL, parameter, CWE, and raw evidence.
Determine whether this alert is a true vulnerability (CONFIRMED) or a false positive (FALSE_POSITIVE).
If the evidence is genuinely ambiguous, return INCONCLUSIVE.
Respond with a single JSON object with keys:
- "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "INCONCLUSIVE"
- "reason": "<concise explanation>"
"""

TRIAGE_USER_TEMPLATE = """Finding: {rule_id} ({source})
CWE: {cwe} ({vuln_class})
Target: {method} {url}
Parameter: {param}
Raw Evidence: {evidence}

Triage this alert."""


def parse_triage_response(text: str) -> tuple[Verdict, str]:
    """Parse JSON or text response into Verdict and reason."""
    # Attempt JSON extraction
    m = re.search(r"\{.*?\}", text, re.DOTALL)
    if m:
        try:
            d = json.loads(m.group(0))
            raw_v = str(d.get("verdict", "")).strip().upper()
            reason = str(d.get("reason", "")).strip()
            if raw_v in Verdict.__members__:
                return Verdict[raw_v], reason or "triage decision"
        except json.JSONDecodeError:
            pass

    # Fallback keyword matching
    upper = text.upper()
    if "FALSE_POSITIVE" in upper or "FALSE POSITIVE" in upper:
        return Verdict.FALSE_POSITIVE, text[:200].strip()
    if "CONFIRMED" in upper or "TRUE POSITIVE" in upper:
        return Verdict.CONFIRMED, text[:200].strip()
    return Verdict.INCONCLUSIVE, text[:200].strip() or "ambiguous alert"


class LLMTriage:
    def __init__(self, llm: Any):
        self.llm = llm

    def triage(self, f: Finding) -> tuple[Verdict, str, int]:
        """Triage a single finding without running any code or sandbox."""
        user_prompt = TRIAGE_USER_TEMPLATE.format(
            rule_id=f.rule_id,
            source=f.source,
            cwe=f.cwe or "unknown",
            vuln_class=f.vuln_class.value,
            method=f.method,
            url=f.url,
            param=f.param or "none",
            evidence=json.dumps(f.raw_evidence),
        )

        tokens_before = getattr(self.llm, "tokens_used", 0)
        resp_text = self.llm.complete(TRIAGE_SYSTEM, user_prompt)
        tokens_after = getattr(self.llm, "tokens_used", 0)
        tokens = max(0, tokens_after - tokens_before)

        verdict, reason = parse_triage_response(resp_text)
        return verdict, reason, tokens

    def triage_all(self, findings: list[Finding]) -> list[dict]:
        """Run zero-shot triage over multiple findings."""
        results = []
        for f in findings:
            verdict, reason, tokens = self.triage(f)
            results.append({
                "key": list(f.dedupe_key),
                "verdict": verdict.value,
                "reason": reason,
                "tokens": tokens,
            })
        return results
