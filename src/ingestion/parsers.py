import json
import re
from pathlib import Path
from .schema import Finding


def _cwe(v) -> int | None:
    if v is None:
        return None
    if isinstance(v, list) and v:
        v = v[0]
    m = re.search(r"cwe[-:]?\s*(\d+)", str(v), re.I)
    if m:
        val = int(m.group(1))
        return val if val > 0 else None
    s = str(v).lower().replace("cwe-", "").strip()
    return int(s) if s.isdigit() and int(s) > 0 else None


def parse_zap(path) -> list[Finding]:
    """ZAP JSON report (traditional-json): site[].alerts[].instances[]."""
    data = json.loads(Path(path).read_text())
    out = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            for inst in alert.get("instances", []):
                out.append(Finding(
                    source="zap", rule_id=str(alert.get("pluginid", alert.get("alert", "?"))),
                    severity=str(alert.get("riskdesc", "unknown")).split(" ")[0].lower(),
                    url=inst.get("uri", ""), method=inst.get("method", "GET"),
                    param=inst.get("param") or None, cwe=_cwe(alert.get("cweid")),
                    raw_evidence={"evidence": inst.get("evidence", ""), "alert": alert.get("alert")},
                ))
    return out


def parse_nuclei(path) -> list[Finding]:
    """Nuclei JSONL (-jsonl)."""
    out = []
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cwes = (r.get("info", {}).get("classification") or {}).get("cwe-id") or []
        cwe_val = _cwe(cwes[0]) if cwes else None
        if not cwe_val:
            tags = r.get("info", {}).get("tags", [])
            tag_str = " ".join(tags) if isinstance(tags, list) else str(tags)
            template_id = r.get("template-id", "").lower()
            combined = f"{template_id} {tag_str.lower()}"
            if "sqli" in combined:
                cwe_val = 89
            elif "xss" in combined:
                cwe_val = 79
            elif "ssrf" in combined:
                cwe_val = 918
            elif "idor" in combined:
                cwe_val = 639
        param = r.get("fuzzing_parameter") or None
        out.append(Finding(
            source="nuclei", rule_id=r.get("template-id", "?"),
            severity=r.get("info", {}).get("severity", "unknown"),
            url=r.get("matched-at", r.get("host", "")), method="GET",
            param=param,
            cwe=cwe_val,
            raw_evidence={"request": r.get("request", ""), "response": r.get("response", "")},
        ))
    return out


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.dedupe_key not in seen:
            seen.add(f.dedupe_key)
            out.append(f)
    return out


def parse_semgrep_sarif(path) -> list[Finding]:
    """Semgrep SARIF report: runs[].results[]."""
    data = json.loads(Path(path).read_text())
    out = []
    level_map = {"error": "high", "warning": "medium", "note": "low"}
    for run in data.get("runs", []):
        rules_map = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "?")
            rule_def = rules_map.get(rule_id, {})
            # Resolve CWE: check result properties first, then rule properties/tags
            cwe_raw = res.get("properties", {}).get("cwe")
            if not cwe_raw:
                cwe_raw = rule_def.get("properties", {}).get("cwe")
            if not cwe_raw:
                for tag in rule_def.get("properties", {}).get("tags", []):
                    if "cwe" in tag.lower():
                        cwe_raw = tag
                        break
            cwe_val = _cwe(cwe_raw)

            # Severity
            raw_level = res.get("level") or rule_def.get("defaultConfiguration", {}).get("level") or "unknown"
            severity = level_map.get(str(raw_level).lower(), str(raw_level).lower())

            # Location
            locs = res.get("locations", [])
            uri, line, snippet = "", None, ""
            if locs:
                phys = locs[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                reg = phys.get("region", {})
                line = reg.get("startLine")
                snippet = reg.get("snippet", {}).get("text", "")

            url = uri if (uri.startswith("http") or uri.startswith("/")) else (f"/{uri}" if uri else "/")
            param = res.get("properties", {}).get("param") or None
            message = res.get("message", {}).get("text", "")

            out.append(Finding(
                source="semgrep",
                rule_id=rule_id,
                severity=severity,
                url=url,
                method="GET",
                param=param,
                cwe=cwe_val,
                raw_evidence={"message": message, "file": uri, "line": line, "snippet": snippet, "rule_id": rule_id},
            ))
    return out
