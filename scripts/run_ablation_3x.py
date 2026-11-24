#!/usr/bin/env python3
"""Runs 3 iterations of the Phase 5 ablation benchmark (Configurations A, B, C)
across the combined dataset (4 true positive + 4 false positive findings),
records metrics, computes mean +/- std, and produces publication-ready charts.
"""
import json
import subprocess
import sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

CREDS_FILE = ROOT_DIR / "lab" / "credentials.json"
assert CREDS_FILE.exists(), "Missing lab/credentials.json"
creds = json.loads(CREDS_FILE.read_text())

TOKEN = creds["user_a"]["token"]
CANARY_VAL = creds["canary_value"]

RUNS = 3
all_metrics = []

for i in range(1, RUNS + 1):
    run_dir = RESULTS_DIR / f"run_{i}"
    run_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}\n>>> STARTING ABLATION BENCHMARK RUN {i}/{RUNS}\n{'='*60}")
    
    # 1. Reset canary hits
    try:
        requests.post("http://localhost:9999/_reset", timeout=5)
        print("Canary hits reset.")
    except Exception as e:
        print(f"Warning resetting canary: {e}")

    # 2. Execute benchmark CLI command
    cmd = [
        "py", "-3.10", "cli.py", "benchmark",
        "--findings", "findings_combined.json",
        "--truth", "lab/ground_truth.json",
        "--target", "http://juiceshop:3000",
        "--model", "qwen2.5-coder:7b",
        "--token", TOKEN,
        "--canary-value", CANARY_VAL,
        "--out-dir", str(run_dir),
    ]
    
    res = subprocess.run(cmd, check=True)
    
    # 3. Collect run metrics
    metrics_path = run_dir / "benchmark_metrics.json"
    assert metrics_path.exists(), f"Missing {metrics_path}"
    m = json.loads(metrics_path.read_text())
    all_metrics.append(m)
    print(f"Run {i} finished: Raw Prec={m['raw']['precision']*100:.1f}%, LLM Prec={m['llm_only']['precision']*100:.1f}%, Verifier Prec={m['verified']['precision']*100:.1f}%, FPRR={m['FPRR_%']:.1f}%")

# Aggregate across 3 runs
summary = {}
configs = ["raw", "llm_only", "verified"]
labels = {
    "raw": "A: Raw Scanner",
    "llm_only": "B: LLM-Only Triage",
    "verified": "C: PoC Verifier (Ours)",
}

for cfg in configs:
    p_list = [m[cfg]["precision"] * 100 for m in all_metrics]
    r_list = [m[cfg]["recall"] * 100 for m in all_metrics]
    f1_list = [m[cfg]["f1"] * 100 for m in all_metrics]
    conf_list = [m[cfg].get("confirmed", 0) for m in all_metrics]
    fp_cnt_list = [m[cfg].get("false_positive", 0) for m in all_metrics]
    inconc_list = [m[cfg].get("inconclusive", 0) for m in all_metrics]
    
    if cfg == "raw":
        fprr_list = [0.0] * RUNS
        strict_fprr_list = [0.0] * RUNS
    elif cfg == "llm_only":
        fprr_list = [m.get("FPRR_llm_%", 0.0) for m in all_metrics]
        strict_fprr_list = [m.get("strict_FPRR_llm_%", m.get("FPRR_llm_%", 0.0)) for m in all_metrics]
    else:
        fprr_list = [m.get("FPRR_%", 0.0) for m in all_metrics]
        strict_fprr_list = [m.get("strict_FPRR_%", m.get("FPRR_%", 0.0)) for m in all_metrics]

    summary[cfg] = {
        "label": labels[cfg],
        "confirmed": {"mean": float(np.mean(conf_list)), "values": conf_list},
        "false_positive": {"mean": float(np.mean(fp_cnt_list)), "values": fp_cnt_list},
        "inconclusive": {"mean": float(np.mean(inconc_list)), "values": inconc_list},
        "precision": {"mean": float(np.mean(p_list)), "std": float(np.std(p_list)), "values": p_list},
        "recall": {"mean": float(np.mean(r_list)), "std": float(np.std(r_list)), "values": r_list},
        "f1": {"mean": float(np.mean(f1_list)), "std": float(np.std(f1_list)), "values": f1_list},
        "fprr": {"mean": float(np.mean(fprr_list)), "std": float(np.std(fprr_list)), "values": fprr_list},
        "strict_fprr": {"mean": float(np.mean(strict_fprr_list)), "std": float(np.std(strict_fprr_list)), "values": strict_fprr_list},
    }

# Save summary JSON
summary_file = RESULTS_DIR / "ablation_summary.json"
summary_file.write_text(json.dumps(summary, indent=2))
print(f"\nSaved summary to {summary_file}")

# Generate aggregated publication chart with error bars
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
fig, ax = plt.subplots(figsize=(10, 6))

x = np.arange(len(configs))
width = 0.25

p_means = [summary[cfg]["precision"]["mean"] for cfg in configs]
p_stds = [summary[cfg]["precision"]["std"] for cfg in configs]

r_means = [summary[cfg]["recall"]["mean"] for cfg in configs]
r_stds = [summary[cfg]["recall"]["std"] for cfg in configs]

f_means = [summary[cfg]["fprr"]["mean"] for cfg in configs]
f_stds = [summary[cfg]["fprr"]["std"] for cfg in configs]

rects1 = ax.bar(x - width, p_means, width, yerr=p_stds, capsize=5, label="Precision (%)", color="#1f77b4")
rects2 = ax.bar(x, r_means, width, yerr=r_stds, capsize=5, label="Recall (%)", color="#2ca02c")
rects3 = ax.bar(x + width, f_means, width, yerr=f_stds, capsize=5, label="FPRR (%)", color="#ff7f0e")

ax.set_ylabel("Percentage (%)", fontsize=12, fontweight="bold")
ax.set_title("Ablation Study: Mean ± Std Across 3 Runs (Juice Shop / DVWA)", fontsize=14, fontweight="bold", pad=15)
ax.set_xticks(x)
ax.set_xticklabels([labels[c] for c in configs], fontsize=11, fontweight="bold")
ax.set_ylim(0, 115)
ax.legend(frameon=True, fontsize=11)

for rects in [rects1, rects2, rects3]:
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f"{height:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 6),
                    textcoords="offset points",
                    ha="center", va="bottom", fontsize=9, fontweight="bold")

plt.tight_layout()
chart_path = RESULTS_DIR / "ablation_mean_std.png"
plt.savefig(chart_path, dpi=300)
plt.close()
print(f"Generated chart: {chart_path}")

print("\n" + "="*95)
print(f"{'Configuration':<24} | {'Conf':<6} | {'FP':<6} | {'Inconc':<7} | {'Precision (%)':<15} | {'Recall (%)':<15} | {'Strict FPRR (%)':<15}")
print("="*95)
for cfg in configs:
    s = summary[cfg]
    c_str = f"{s['confirmed']['mean']:.1f}"
    fp_str = f"{s['false_positive']['mean']:.1f}"
    inc_str = f"{s['inconclusive']['mean']:.1f}"
    p_str = f"{s['precision']['mean']:.1f} ± {s['precision']['std']:.1f}"
    r_str = f"{s['recall']['mean']:.1f} ± {s['recall']['std']:.1f}"
    f_str = f"{s['strict_fprr']['mean']:.1f} ± {s['strict_fprr']['std']:.1f}"
    print(f"{s['label']:<24} | {c_str:<6} | {fp_str:<6} | {inc_str:<7} | {p_str:<15} | {r_str:<15} | {f_str:<15}")
print("="*95)
