"""Publication-ready 300 DPI charts for thesis evaluation using matplotlib."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def generate_thesis_charts(summary: dict, c_results: list[dict], out_dir: str | Path) -> dict[str, Path]:
    """Generate 300 DPI thesis figures:
    - ablation_metrics.png: Grouped bar chart comparing Precision, Recall, Strict FPRR across A, B1, B2, C
    - latency_vs_precision.png: Trade-off plot comparing mean latency per finding vs Precision
    - retry_distribution.png: Attempt resolution distribution for Config C
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    generated = {}

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.labelsize": 11,
        "axes.labelweight": "bold",
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "figure.titlesize": 14,
    })

    # =========================================================================
    # 1. ablation_metrics.png (Grouped Bar Chart across A, B1, B2, C)
    # =========================================================================
    configs = []
    labels = []
    p_means, p_errs = [], []
    r_means, r_errs = [], []
    f_means, f_errs = [], []

    cfg_keys = [
        ("raw", "A: Raw Scanner"),
        ("llm_only", "B1: Zero-Shot LLM"),
        ("llm_cot", "B2: Skeptical CoT"),
        ("verified", "C: VeriPoC (Ours)"),
    ]

    for k, lab in cfg_keys:
        if k in summary:
            configs.append(k)
            labels.append(lab)
            p = summary[k].get("precision", {})
            r = summary[k].get("recall", {})
            f = summary[k].get("strict_fprr", summary[k].get("fprr", {}))

            p_means.append(p.get("mean", 0.0))
            p_errs.append(p.get("std", 0.0))
            r_means.append(r.get("mean", 0.0))
            r_errs.append(r.get("std", 0.0))
            f_means.append(f.get("mean", 0.0))
            f_errs.append(f.get("std", 0.0))

    if configs:
        fig, ax = plt.subplots(figsize=(9.5, 5.5))
        x = np.arange(len(configs))
        width = 0.26

        rects1 = ax.bar(x - width, p_means, width, yerr=p_errs, capsize=4,
                        label="Precision (%)", color="#1f77b4", edgecolor="#0e4369", linewidth=1.2)
        rects2 = ax.bar(x, r_means, width, yerr=r_errs, capsize=4,
                        label="Recall (%)", color="#2ca02c", edgecolor="#145914", linewidth=1.2)
        rects3 = ax.bar(x + width, f_means, width, yerr=f_errs, capsize=4,
                        label="Strict FPRR (%)", color="#ff7f0e", edgecolor="#8c4404", linewidth=1.2)

        ax.set_ylabel("Score (%)")
        ax.set_title("Ablation Study: Precision, Recall, and Strict FPRR across Configurations")
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylim(0, 115)
        ax.legend(loc="upper left", framealpha=0.95)
        ax.grid(axis="y", linestyle="--", alpha=0.5)

        # Annotate bar values
        def autolabel(rects):
            for rect in rects:
                h = rect.get_height()
                ax.annotate(f"{h:.1f}%",
                            xy=(rect.get_x() + rect.get_width() / 2, h),
                            xytext=(0, 4), textcoords="offset points",
                            ha="center", va="bottom", fontsize=8.5, fontweight="bold")
        autolabel(rects1)
        autolabel(rects2)
        autolabel(rects3)

        plt.tight_layout()
        p1 = out_path / "ablation_metrics.png"
        plt.savefig(p1, dpi=300)
        plt.close(fig)
        generated["ablation_metrics"] = p1

    # =========================================================================
    # 2. latency_vs_precision.png (Latency vs Precision Trade-off)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8, 5.2))
    points = []
    # Collect points for each config: (label, mean_latency_s, precision_%, color, marker)
    color_map = {
        "raw": ("A: Raw Scanner", 0.05, summary.get("raw", {}).get("precision", {}).get("mean", 50.0), "#7f7f7f", "s"),
        "llm_only": ("B1: Zero-Shot LLM", summary.get("llm_only", {}).get("latency_per_finding", {}).get("mean", 1.2),
                     summary.get("llm_only", {}).get("precision", {}).get("mean", 50.0), "#1f77b4", "o"),
        "llm_cot": ("B2: Skeptical CoT", summary.get("llm_cot", {}).get("latency_per_finding", {}).get("mean", 2.8),
                    summary.get("llm_cot", {}).get("precision", {}).get("mean", 60.0), "#9467bd", "^"),
        "verified": ("C: VeriPoC (Ours)", summary.get("verified", {}).get("latency_per_finding", {}).get("mean", 4.5),
                     summary.get("verified", {}).get("precision", {}).get("mean", 100.0), "#2ca02c", "*"),
    }

    for k, (lab, lat, prec, col, mark) in color_map.items():
        if k in summary:
            # Overwrite latency if logged in summary
            lat_actual = summary[k].get("latency_per_finding", {}).get("mean", lat)
            prec_actual = summary[k].get("precision", {}).get("mean", prec)
            ax.scatter([lat_actual], [prec_actual], color=col, s=200 if mark == "*" else 130,
                       marker=mark, label=lab, zorder=5, edgecolors="#111111", linewidth=1.2)
            # Offset text annotation
            offset_y = 3 if k == "verified" else (-6 if k == "llm_only" else 4)
            offset_x = 0.15 if lat_actual > 0.5 else 0.08
            ax.annotate(f"{lab}\n({lat_actual:.1f}s, {prec_actual:.1f}%)",
                        xy=(lat_actual, prec_actual),
                        xytext=(lat_actual + offset_x, prec_actual + offset_y),
                        fontsize=9.5, fontweight="bold",
                        bbox=dict(boxstyle="round,pad=0.3", fc="#f8f9fa", ec=col, alpha=0.9))

    ax.set_xlabel("Mean Wall-Clock Latency per Finding (seconds)")
    ax.set_ylabel("Verification Precision (%)")
    ax.set_title("Latency vs. Precision Frontier Across Triage Architectures")
    ax.set_ylim(0, 115)
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(loc="lower right", framealpha=0.95)
    plt.tight_layout()
    p2 = out_path / "latency_vs_precision.png"
    plt.savefig(p2, dpi=300)
    plt.close(fig)
    generated["latency_vs_precision"] = p2

    # =========================================================================
    # 3. retry_distribution.png (Resolution by Attempt Number for Config C)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    attempt_counts = {1: 0, 2: 0, 3: 0}
    total_findings = max(1, len(c_results))

    for r in c_results:
        attempts_used = r.get("attempts", len(r.get("history", [])))
        attempts_clamped = min(3, max(1, attempts_used))
        attempt_counts[attempts_clamped] += 1

    x_att = [1, 2, 3]
    labels_att = ["Attempt 1\n(First Pass)", "Attempt 2\n(Self-Correction)", "Attempt 3\n(Final Retry)"]
    pcts = [(attempt_counts[i] / total_findings) * 100 for i in x_att]
    raw_nums = [attempt_counts[i] for i in x_att]

    colors_att = ["#2ecc71", "#3498db", "#e67e22"]
    bars = ax.bar(x_att, pcts, color=colors_att, width=0.55, edgecolor="#222222", linewidth=1.2)

    ax.set_xticks(x_att)
    ax.set_xticklabels(labels_att)
    ax.set_ylabel("Percentage of Findings Resolved (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Config C (VeriPoC) Convergence: Resolution Distribution by Attempt")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for bar, pct, raw in zip(bars, pcts, raw_nums):
        h = bar.get_height()
        ax.annotate(f"{pct:.1f}%\n({raw} findings)",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=9.5, fontweight="bold")

    plt.tight_layout()
    p3 = out_path / "retry_distribution.png"
    plt.savefig(p3, dpi=300)
    plt.close(fig)
    generated["retry_distribution"] = p3

    return generated
