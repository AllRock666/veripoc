import json
from src.ingestion.schema import Finding, VulnClass, Verdict
from src.reporting.baseline_b import LLMTriage, SkepticalCoTTriage, parse_triage_response, parse_triage_response_full
from src.reporting.metrics import compare


class MockTriageLLM:
    def __init__(self, canned_response: str, tokens: int = 150):
        self.response = canned_response
        self.tokens_used = 0
        self.token_step = tokens

    def complete(self, system: str, user: str) -> str:
        self.tokens_used += self.token_step
        return self.response


def test_parse_triage_response():
    v, r = parse_triage_response('{"verdict": "CONFIRMED", "reason": "payload reflected directly"}')
    assert v == Verdict.CONFIRMED
    assert r == "payload reflected directly"

    v, r = parse_triage_response('{"verdict": "FALSE_POSITIVE", "reason": "properly escaped"}')
    assert v == Verdict.FALSE_POSITIVE

    # Fallback keyword matching
    v, r = parse_triage_response("Based on analysis this is a False Positive.")
    assert v == Verdict.FALSE_POSITIVE

    v, r = parse_triage_response("I cannot tell from this snippet alone.")
    assert v == Verdict.INCONCLUSIVE


def test_baseline_b_triage():
    f = Finding(
        source="zap",
        rule_id="40018",
        url="http://target/rest/products/search?q=1",
        param="q",
        cwe=89,
        vuln_class=VulnClass.SQLI,
    )
    llm = MockTriageLLM('{"verdict": "CONFIRMED", "reason": "raw SQL query concatenation"}', tokens=120)
    triage = LLMTriage(llm)

    v, reason, tokens = triage.triage(f)
    assert v == Verdict.CONFIRMED
    assert "concatenation" in reason
    assert tokens == 120


def test_skeptical_cot_triage():
    f = Finding(
        source="zap",
        rule_id="40012",
        url="http://target/#/contact?name=test",
        param="name",
        cwe=79,
        vuln_class=VulnClass.XSS,
    )
    llm = MockTriageLLM(
        '{"reasoning": "Angular SPA context-encodes values in template bindings.", "verdict": "FALSE_POSITIVE", "reason": "client sanitization disarms script"}',
        tokens=250,
    )
    triage = SkepticalCoTTriage(llm)
    results = triage.triage_all([f])
    assert len(results) == 1
    assert results[0]["verdict"] == "FALSE_POSITIVE"
    assert "Angular SPA" in results[0]["reasoning"]
    assert results[0]["tokens"] == 250


def test_baseline_b_ablation_metrics():
    # Ground truth: /a is real vuln, /b is FP, /c is real vuln
    truth = {
        ("/a", "q", 89): True,
        ("/b", "q", 89): False,
        ("/c", "p", 79): True,
    }
    raw_keys = set(truth.keys())  # Baseline A: claims all 3 are vulnerable
    # Baseline B (LLM-only): predicts /a and /b as vulnerable (fails to catch FP /b)
    llm_confirmed = {("/a", "q", 89), ("/b", "q", 89)}
    # Baseline C (Our system): correctly eliminates /b, confirms /a and /c
    ver_confirmed = {("/a", "q", 89), ("/c", "p", 79)}

    metrics = compare(raw_keys, ver_confirmed, truth, llm_confirmed=llm_confirmed)

    # Baseline A (raw scanner)
    assert metrics["raw"]["precision"] == 2 / 3
    assert metrics["raw"]["fp"] == 1

    # Baseline B (LLM-only)
    assert metrics["llm_only"]["precision"] == 1 / 2
    assert metrics["llm_only"]["fp"] == 1
    assert metrics["FPRR_llm_%"] == 0.0

    # Baseline C (LLM + sandbox + oracles)
    assert metrics["verified"]["precision"] == 1.0
    assert metrics["verified"]["fp"] == 0
    assert metrics["FPRR_%"] == 100.0
