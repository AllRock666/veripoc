"""Human-readable Markdown triage report exporter for VeriPoC."""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from .metrics import FailureModeTaxonomy


def export_markdown_triage_report(
    c_results: list[dict],
    output_path: str | Path,
    run_metadata: dict | None = None,
    metrics: dict | None = None,
) -> Path:
    """Generate a publication-grade human-readable Markdown triage report.

    - Lists all CONFIRMED findings first with URL, CWE, deterministic oracle proof,
      and the exact verification script that succeeded.
    - Groups FALSE_POSITIVE and INCONCLUSIVE findings into concise summary tables
      with their oracle rationale and failure-mode taxonomy category.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    confirmed = [r for r in c_results if r.get("verdict") == "CONFIRMED"]
    false_positives = [r for r in c_results if r.get("verdict") == "FALSE_POSITIVE"]
    inconclusive = [r for r in c_results if r.get("verdict") == "INCONCLUSIVE"]

    lines = []
    lines.append("# Autonomous PoC Verifier (VeriPoC) - Triage Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if run_metadata:
        lines.append(f"- **Git Commit:** `{run_metadata.get('git_commit', 'unknown')}`")
        lines.append(f"- **Python Version:** `{run_metadata.get('python_version', 'unknown')}`")
        lines.append(f"- **Docker Version:** `{run_metadata.get('docker_version', 'unknown')}`")
        lines.append(f"- **Ollama Model:** `{run_metadata.get('ollama_model', 'qwen2.5-coder:7b')}`")
    lines.append("")

    # Executive Summary Table
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Metric | Count / Percentage |")
    lines.append("| :--- | :--- |")
    lines.append(f"| Total Scanner Alerts Evaluated | {len(c_results)} |")
    lines.append(f"| Confirmed Vulnerabilities (True Positives) | {len(confirmed)} |")
    lines.append(f"| Eliminated False Positives | {len(false_positives)} |")
    lines.append(f"| Inconclusive Alerts | {len(inconclusive)} |")
    if metrics:
        v_m = metrics.get("verified", {})
        lines.append(f"| Pipeline Precision | {v_m.get('precision', 0.0) * 100:.1f}% |")
        lines.append(f"| Pipeline Recall | {v_m.get('recall', 0.0) * 100:.1f}% |")
        lines.append(f"| Strict False-Positive Reduction Rate (FPRR) | {metrics.get('strict_FPRR_%', 0.0):.1f}% |")
    lines.append("")

    # Section 1: Confirmed Findings (with proof and scripts)
    lines.append("## 1. Confirmed Vulnerabilities (Empirical Proofs)")
    lines.append("")
    if not confirmed:
        lines.append("*No vulnerabilities were confirmed in this evaluation.*")
        lines.append("")
    else:
        for i, item in enumerate(confirmed, 1):
            key = item.get("key", ["", "", 0])
            endpoint = key[0] if len(key) > 0 else "unknown"
            param = key[1] if len(key) > 1 else "none"
            cwe = key[2] if len(key) > 2 else 0

            history = item.get("history", [])
            last_script = history[-1].get("script", "") if history else ""
            attempts = item.get("attempts", len(history))
            dur = item.get("duration_s", 0.0)
            tok = item.get("tokens", 0)

            lines.append(f"### 1.{i}. {endpoint} (CWE-{cwe})")
            lines.append(f"- **Target URL:** `{endpoint}`")
            lines.append(f"- **Vulnerable Parameter:** `{param}`")
            lines.append(f"- **Deterministic Oracle Proof:** {item.get('reason', 'Empirically confirmed')}")
            lines.append(f"- **Convergence:** Resolved on Attempt {attempts} ({dur:.2f}s wall-clock, {tok} LLM tokens)")
            lines.append("")
            lines.append("```python")
            lines.append("# Succeeded Verification Script:")
            lines.append(last_script.strip() if last_script else "# (Script content recorded in attempt logs)")
            lines.append("```")
            lines.append("")

    # Section 2: Eliminated False Positives Table
    lines.append("## 2. Eliminated False Positives")
    lines.append("")
    if not false_positives:
        lines.append("*No false positives were eliminated in this evaluation.*")
        lines.append("")
    else:
        lines.append("| Endpoint | Parameter | CWE | Oracle Verdict Reason | Latency |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for item in false_positives:
            key = item.get("key", ["", "", 0])
            ep = key[0] if len(key) > 0 else ""
            p = key[1] if len(key) > 1 else "none"
            c = key[2] if len(key) > 2 else 0
            reason = item.get("reason", "No vulnerability observed").replace("|", "\\|")
            dur = item.get("duration_s", 0.0)
            lines.append(f"| `{ep}` | `{p}` | CWE-{c} | {reason} | {dur:.2f}s |")
        lines.append("")

    # Section 3: Inconclusive Findings & Failure Taxonomy Table
    lines.append("## 3. Inconclusive Findings & Failure Taxonomy")
    lines.append("")
    if not inconclusive:
        lines.append("*Zero findings resulted in an INCONCLUSIVE outcome.*")
        lines.append("")
    else:
        lines.append("| Endpoint | Parameter | CWE | Failure Mode | Failure Rationale | Attempts |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for item in inconclusive:
            key = item.get("key", ["", "", 0])
            ep = key[0] if len(key) > 0 else ""
            p = key[1] if len(key) > 1 else "none"
            c = key[2] if len(key) > 2 else 0
            history = item.get("history", [])
            mode = FailureModeTaxonomy.OTHER
            if history:
                last_att = history[-1]
                mode = FailureModeTaxonomy.classify(
                    exit_code=last_att.get("exit_code", 0),
                    stdout=last_att.get("stdout", ""),
                    stderr=last_att.get("stderr", ""),
                    reason=item.get("reason", ""),
                )
            else:
                mode = FailureModeTaxonomy.classify(reason=item.get("reason", ""))
            reason = item.get("reason", "Inconclusive").replace("|", "\\|")
            att_cnt = item.get("attempts", len(history))
            lines.append(f"| `{ep}` | `{p}` | CWE-{c} | `{mode}` | {reason} | {att_cnt} |")
        lines.append("")

    content = "\n".join(lines)
    out_file.write_text(content, encoding="utf-8")
    return out_file
