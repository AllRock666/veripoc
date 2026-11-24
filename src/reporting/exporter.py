"""Exporters for verification findings: CSV tabular export and publication-grade matplotlib charts."""
from __future__ import annotations
import csv
from pathlib import Path
from typing import Any
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from .taxonomy import classify_finding_failure, FailureMode


def export_results_csv(findings_data: list[dict], csv_path: str | Path) -> Path:
    """Export verification findings to CSV with duration, token counts, and failure taxonomy."""
    path = Path(csv_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "endpoint",
        "param",
        "cwe",
        "verdict",
        "reason",
        "attempts",
        "duration_s",
        "tokens",
        "failure_mode",
        "ground_truth",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings_data:
            key = item.get("key", ["", "", 0])
            attempts_list = item.get("history", [])
            attempts_count = item.get("attempts", len(attempts_list))
            total_duration = item.get("duration_s", sum(a.get("duration_s", 0.0) for a in attempts_list))
            total_tokens = item.get("tokens", sum(a.get("tokens", 0) for a in attempts_list))

            verdict = item.get("verdict", "INCONCLUSIVE")
            if verdict == "INCONCLUSIVE":
                failure_mode = item.get("failure_mode") or classify_finding_failure(attempts_list).value
            else:
                failure_mode = "none"

            row = {
                "endpoint": key[0] if len(key) > 0 else "",
                "param": key[1] if len(key) > 1 else "",
                "cwe": key[2] if len(key) > 2 else 0,
                "verdict": verdict,
                "reason": item.get("reason", ""),
                "attempts": attempts_count,
                "duration_s": round(float(total_duration), 2),
                "tokens": int(total_tokens),
                "failure_mode": failure_mode,
                "ground_truth": item.get("ground_truth", ""),
            }
            writer.writerow(row)
    return path


def generate_plots(metrics: dict, findings_data: list[dict], out_dir: str | Path) -> dict[str, Path]:
    """Generate precision/recall/FPRR comparison, cost vs latency, and failure taxonomy charts."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    generated = {}

    # 1. Precision / Recall / FPRR Bar Chart
    plt.figure(figsize=(9, 5))
    configs = []
    precision_vals = []
    recall_vals = []
    fprr_vals = []

    # Config A: Raw scanner
    if "raw" in metrics:
        configs.append("A: Raw Scanner")
        precision_vals.append(metrics["raw"].get("precision", 0.0) * 100)
        recall_vals.append(metrics["raw"].get("recall", 0.0) * 100)
        fprr_vals.append(0.0)

    # Config B: LLM-only triage
    if "llm_only" in metrics:
        configs.append("B: LLM-Only")
        precision_vals.append(metrics["llm_only"].get("precision", 0.0) * 100)
        recall_vals.append(metrics["llm_only"].get("recall", 0.0) * 100)
        fprr_vals.append(metrics.get("FPRR_llm_%", 0.0))

    # Config C: Verifier (Ours)
    if "verified" in metrics:
        configs.append("C: PoC Verifier (Ours)")
        precision_vals.append(metrics["verified"].get("precision", 0.0) * 100)
        recall_vals.append(metrics["verified"].get("recall", 0.0) * 100)
        fprr_vals.append(metrics.get("FPRR_%", 0.0))

    if configs:
        import numpy as np
        x = np.arange(len(configs))
        width = 0.25

        plt.bar(x - width, precision_vals, width, label="Precision (%)", color="#2980b9")
        plt.bar(x, recall_vals, width, label="Recall (%)", color="#27ae60")
        plt.bar(x + width, fprr_vals, width, label="FPRR (%)", color="#e67e22")

        plt.xlabel("Ablation Configuration", fontweight="bold")
        plt.ylabel("Score (%)", fontweight="bold")
        plt.title("Ablation Study: Precision, Recall, and False-Positive Reduction Rate", fontweight="bold")
        plt.xticks(x, configs)
        plt.ylim(0, 110)
        plt.legend(loc="lower right")
        plt.grid(axis="y", linestyle="--", alpha=0.7)
        plt.tight_layout()

        chart1_path = out_path / "precision_recall_fprr.png"
        plt.savefig(chart1_path, dpi=200)
        plt.close()
        generated["comparison"] = chart1_path

    # 2. Cost vs Latency Scatter Plot
    plt.figure(figsize=(8, 5))
    durations, tokens, colors, labels = [], [], [], []
    color_map = {
        "CONFIRMED": "#27ae60",
        "FALSE_POSITIVE": "#c0392b",
        "INCONCLUSIVE": "#f39c12",
    }

    for item in findings_data:
        attempts_list = item.get("history", [])
        dur = item.get("duration_s", sum(a.get("duration_s", 0.0) for a in attempts_list))
        tok = item.get("tokens", sum(a.get("tokens", 0) for a in attempts_list))
        v = item.get("verdict", "INCONCLUSIVE")
        durations.append(dur)
        tokens.append(tok)
        colors.append(color_map.get(v, "#7f8c8d"))

    if durations and tokens:
        plt.scatter(durations, tokens, c=colors, s=70, alpha=0.8, edgecolors="none")
        # Add legend handles
        for v, c in color_map.items():
            plt.scatter([], [], c=c, label=v, s=50)

        plt.xlabel("Wall-Clock Latency (seconds)", fontweight="bold")
        plt.ylabel("Token Cost (LLM tokens)", fontweight="bold")
        plt.title("Per-Finding Verification Cost vs. Latency", fontweight="bold")
        plt.legend(loc="upper left")
        plt.grid(True, linestyle="--", alpha=0.6)
        plt.tight_layout()

        chart2_path = out_path / "cost_vs_latency.png"
        plt.savefig(chart2_path, dpi=200)
        plt.close()
        generated["cost_vs_latency"] = chart2_path

    # 3. Failure Mode Taxonomy Breakdown
    inconclusive_findings = [f for f in findings_data if f.get("verdict") == "INCONCLUSIVE"]
    if inconclusive_findings:
        counts = {m.value: 0 for m in FailureMode}
        for item in inconclusive_findings:
            mode = item.get("failure_mode") or classify_finding_failure(item.get("history", [])).value
            counts[mode] = counts.get(mode, 0) + 1

        plt.figure(figsize=(7, 4))
        modes = list(counts.keys())
        freqs = [counts[m] for m in modes]
        plt.barh(modes, freqs, color="#8e44ad")
        plt.xlabel("Number of Findings", fontweight="bold")
        plt.title("INCONCLUSIVE Failure-Mode Taxonomy Breakdown", fontweight="bold")
        plt.grid(axis="x", linestyle="--", alpha=0.7)
        plt.tight_layout()

        chart3_path = out_path / "failure_taxonomy.png"
        plt.savefig(chart3_path, dpi=200)
        plt.close()
        generated["failure_taxonomy"] = chart3_path

    return generated
