"""Baseline B: Zero-shot (B1) and Skeptical Chain-of-Thought (B2) LLM triage of raw scanner alerts with NO sandbox execution."""
from __future__ import annotations
import json
import re
from typing import Any
from ..ingestion.schema import Finding, Verdict

# Baseline B1: Standard Zero-Shot Triage
TRIAGE_SYSTEM = """You are an AppSec vulnerability triage expert.
Analyze the given automated scanner alert, including target URL, parameter, CWE, and raw evidence.
Determine whether this alert is a true vulnerability (CONFIRMED) or a false positive (FALSE_POSITIVE).
If the evidence is genuinely ambiguous, return INCONCLUSIVE.
Respond with a single JSON object with keys:
- "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "INCONCLUSIVE"
- "reason": "<concise explanation>"
"""

# Baseline B2: Skeptical Chain-of-Thought Triage
SKEPTICAL_COT_SYSTEM = """You are a senior AppSec analyst specializing in defensive triage of automated scanner alerts.
Automated DAST and SAST tools (ZAP, Nuclei, Semgrep) frequently produce false positives. Be rigorous and skeptical:
- Angular/React client-side sanitization: Reflected payloads in Angular/React SPAs (e.g., #/ routes or template bindings) are sanitized by the client framework unless an explicit bypass exists. Merely observing reflected text in an HTTP response is NOT proof of XSS.
- ORM / Parameterized queries: SQL error banners or reflected inputs often occur in ORM-managed or parameterized endpoints (e.g., Sequelize/Hibernate) where injection into the SQL execution tree is impossible.
- HTTP 200 OK / Reflection: An HTTP 200 status or parameter reflection is standard application behavior, NOT evidence of SSRF or IDOR.
- Splicing / URL parsing: Alert evidence must show unambiguous proof of execution, state alteration, or unauthorized data access, not merely theoretical possibility.

Perform step-by-step chain-of-thought analysis:
1. Examine the scanner evidence critically: Does it prove actual exploitation/execution, or merely benign reflection or framework error?
2. Consider modern framework defenses (ORM parameterization, Angular DOM sanitization, authorization layers).
3. Conclude whether this alert is a confirmed vulnerability (CONFIRMED), an unexploitable false positive (FALSE_POSITIVE), or genuinely ambiguous (INCONCLUSIVE).

Respond with a single JSON object with keys:
- "reasoning": "<step-by-step chain-of-thought analysis in 2-3 concise sentences>"
- "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "INCONCLUSIVE"
- "reason": "<concise summary explanation>"
"""

TRIAGE_USER_TEMPLATE = """Finding: {rule_id} ({source})
CWE: {cwe} ({vuln_class})
Target: {method} {url}
Parameter: {param}
Raw Evidence: {evidence}

Triage this alert."""


def parse_triage_response_full(text: str) -> tuple[Verdict, str, str]:
    """Parse JSON or text response into (Verdict, reason, reasoning)."""
    # Attempt JSON extraction
    m = re.search(r"\{.*?\}", text, re.DOTALL)
    if m:
        try:
            d = json.loads(m.group(0))
            raw_v = str(d.get("verdict", "")).strip().upper()
            reason = str(d.get("reason", "")).strip()
            reasoning = str(d.get("reasoning", "")).strip()
            if raw_v in Verdict.__members__:
                return Verdict[raw_v], reason or "triage decision", reasoning
        except json.JSONDecodeError:
            pass

    # Fallback keyword matching
    upper = text.upper()
    if "FALSE_POSITIVE" in upper or "FALSE POSITIVE" in upper:
        return Verdict.FALSE_POSITIVE, text[:200].strip(), text.strip()
    if "CONFIRMED" in upper or "TRUE POSITIVE" in upper:
        return Verdict.CONFIRMED, text[:200].strip(), text.strip()
    return Verdict.INCONCLUSIVE, text[:200].strip() or "ambiguous alert", text.strip()


def parse_triage_response(text: str) -> tuple[Verdict, str]:
    """Backwards-compatible parser returning (Verdict, reason)."""
    v, reason, _ = parse_triage_response_full(text)
    return v, reason


class LLMTriage:
    def __init__(self, llm: Any, system_prompt: str = TRIAGE_SYSTEM):
        self.llm = llm
        self.system_prompt = system_prompt

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
        resp_text = self.llm.complete(self.system_prompt, user_prompt)
        tokens_after = getattr(self.llm, "tokens_used", 0)
        tokens = max(0, tokens_after - tokens_before)

        verdict, reason, self._last_reasoning = parse_triage_response_full(resp_text)
        return verdict, reason, tokens

    def triage_all(self, findings: list[Finding]) -> list[dict]:
        """Run triage over multiple findings."""
        results = []
        for f in findings:
            verdict, reason, tokens = self.triage(f)
            rec = {
                "key": list(f.dedupe_key),
                "verdict": verdict.value,
                "reason": reason,
                "tokens": tokens,
            }
            if getattr(self, "_last_reasoning", None):
                rec["reasoning"] = self._last_reasoning
            results.append(rec)
        return results


class SkepticalCoTTriage(LLMTriage):
    """Baseline B2: Skeptical Chain-of-Thought LLM Triage."""
    def __init__(self, llm: Any):
        super().__init__(llm, system_prompt=SKEPTICAL_COT_SYSTEM)
