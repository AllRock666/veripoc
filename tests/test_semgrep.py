import json
from src.ingestion.parsers import parse_semgrep_sarif, deduplicate
from src.ingestion.schema import VulnClass


def test_parse_semgrep_sarif_basic(tmp_path):
    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": "rules.security.sqli",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {
                                    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "rules.security.sqli",
                        "level": "error",
                        "message": {"text": "Potential SQL injection vulnerability"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "routes/search.js"},
                                    "region": {
                                        "startLine": 42,
                                        "snippet": {"text": "db.query('SELECT * FROM products WHERE q=' + req.query.q)"},
                                    },
                                }
                            }
                        ],
                        "properties": {"param": "q"},
                    }
                ],
            }
        ],
    }
    p = tmp_path / "semgrep.sarif"
    p.write_text(json.dumps(sarif))

    findings = parse_semgrep_sarif(p)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "semgrep"
    assert f.rule_id == "rules.security.sqli"
    assert f.severity == "high"
    assert f.cwe == 89
    assert f.vuln_class == VulnClass.SQLI
    assert f.url == "/routes/search.js"
    assert f.path == "/routes/search.js"
    assert f.param == "q"
    assert f.raw_evidence["line"] == 42
    assert "db.query" in f.raw_evidence["snippet"]


def test_parse_semgrep_cwe_fallbacks_and_dedupe(tmp_path):
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [
                            {
                                "id": "rule.ssrf",
                                "properties": {"tags": ["OWASP-A10", "CWE-918"]},
                            },
                            {
                                "id": "rule.xss",
                                "properties": {},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "rule.ssrf",
                        "level": "warning",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "http://target/fetch"}}}],
                    },
                    {
                        "ruleId": "rule.xss",
                        "level": "note",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/view"}}}],
                        "properties": {"cwe": "CWE-79", "param": "name"},
                    },
                    # Duplicate of the XSS finding
                    {
                        "ruleId": "rule.xss",
                        "level": "note",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/view"}}}],
                        "properties": {"cwe": "CWE-79", "param": "name"},
                    },
                ],
            }
        ],
    }
    p = tmp_path / "semgrep_multi.sarif"
    p.write_text(json.dumps(sarif))

    findings = parse_semgrep_sarif(p)
    assert len(findings) == 3
    assert findings[0].vuln_class == VulnClass.SSRF
    assert findings[0].severity == "medium"
    assert findings[0].cwe == 918

    assert findings[1].vuln_class == VulnClass.XSS
    assert findings[1].severity == "low"
    assert findings[1].cwe == 79
    assert findings[1].param == "name"

    deduped = deduplicate(findings)
    assert len(deduped) == 2


def test_parse_semgrep_empty(tmp_path):
    p = tmp_path / "empty.sarif"
    p.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    assert parse_semgrep_sarif(p) == []


def test_cli_ingest_semgrep(tmp_path):
    from typer.testing import CliRunner
    from cli import app

    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "rules": []}},
                "results": [
                    {
                        "ruleId": "test.rule",
                        "level": "error",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/api/test"}}}],
                        "properties": {"cwe": "89"},
                    }
                ],
            }
        ],
    }
    sarif_file = tmp_path / "semgrep.sarif"
    sarif_file.write_text(json.dumps(sarif))
    out_file = tmp_path / "out.json"

    runner = CliRunner()
    res = runner.invoke(app, ["ingest", "--semgrep", str(sarif_file), "--out", str(out_file)])
    assert res.exit_code == 0
    assert "1 unique findings" in res.stdout
    data = json.loads(out_file.read_text())
    assert len(data) == 1
    assert data[0]["source"] == "semgrep"
    assert data[0]["cwe"] == 89
