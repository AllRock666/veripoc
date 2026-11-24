import json
from src.ingestion.parsers import parse_zap, parse_nuclei, deduplicate
from src.ingestion.schema import Verdict, VulnClass, Finding
from src.oracles.base import OracleContext, evaluate
from src.reporting.metrics import compare


def test_zap_and_dedupe(tmp_path):
    rep = {"site": [{"alerts": [{"pluginid": "40018", "alert": "SQLi", "riskdesc": "High (Medium)", "cweid": "89",
            "instances": [{"uri": "http://t/rest/products/search?q=1", "method": "GET", "param": "q"},
                          {"uri": "http://t/rest/products/search?q=2", "method": "GET", "param": "q"}]}]}]}
    p = tmp_path / "z.json"; p.write_text(json.dumps(rep))
    fs = parse_zap(p)
    assert len(fs) == 2 and fs[0].vuln_class == VulnClass.SQLI
    assert len(deduplicate(fs)) == 1


def test_nuclei(tmp_path):
    p = tmp_path / "n.jsonl"
    p.write_text(json.dumps({"template-id": "x", "matched-at": "http://t/a", "info": {"severity": "high",
                 "classification": {"cwe-id": ["cwe-918"]}}}) + "\n")
    assert parse_nuclei(p)[0].vuln_class == VulnClass.SSRF


F = lambda c: Finding(source="t", rule_id="r", url="http://t/x", cwe=c)


def test_sqli_time_oracle():
    ok = {"completed": True, "baseline_ms": [100, 120], "payload_ms": [3200, 3150], "delay_s": 3}
    no = {"completed": True, "baseline_ms": [100, 120], "payload_ms": [130, 110], "delay_s": 3}
    assert evaluate(F(89), ok, OracleContext()).verdict == Verdict.CONFIRMED
    assert evaluate(F(89), no, OracleContext()).verdict == Verdict.FALSE_POSITIVE
    assert evaluate(F(89), {"completed": False}, OracleContext()).verdict == Verdict.INCONCLUSIVE


def test_ssrf_idor_xss():
    assert evaluate(F(918), {"completed": True, "token": "abc"},
                    OracleContext(canary_hits=[{"path": "/abc"}])).verdict == Verdict.CONFIRMED
    assert evaluate(F(918), {"completed": True, "token": "abc"}, OracleContext()).verdict == Verdict.FALSE_POSITIVE
    assert evaluate(F(639), {"completed": True, "status": 200, "body": "SECRET-B"},
                    OracleContext(canary_value="SECRET-B")).verdict == Verdict.CONFIRMED
    assert evaluate(F(79), {"completed": True, "xss_fired": False}, OracleContext()).verdict == Verdict.FALSE_POSITIVE


def test_metrics():
    truth = {("/a", "q", 89): True, ("/b", "q", 89): False}
    r = compare(set(truth), {("/a", "q", 89)}, truth)
    assert r["raw"]["precision"] == 0.5 and r["verified"]["precision"] == 1.0 and r["FPRR_%"] == 100.0


def test_finding_db_engine():
    f_juice = Finding(source="zap", rule_id="1", url="http://juiceshop:3000/rest/products/search?q=1", cwe=89)
    f_dvwa = Finding(source="zap", rule_id="2", url="http://dvwa:80/vulnerabilities/sqli/?id=1", cwe=89)
    f_port = Finding(source="zap", rule_id="3", url="http://127.0.0.1:4280/vulnerabilities/sqli/?id=1", cwe=89)
    assert f_juice.db_engine == "sqlite"
    assert f_dvwa.db_engine == "mysql"
    assert f_port.db_engine == "mysql"
