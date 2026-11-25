#!/usr/bin/env python3
"""Runs 3 iterations of the Phase 5 ablation benchmark (Configurations A, B1, B2, C)
across the expanded 20-finding dataset, records metrics, computes mean +/- std,
and produces 300 DPI publication-ready charts and failure taxonomy.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.reporting.charts import generate_thesis_charts
from src.reporting.metrics import FailureModeTaxonomy

RESULTS_DIR = ROOT_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)
CHARTS_DIR = RESULTS_DIR / "charts"
CHARTS_DIR.mkdir(parents=True, exist_ok=True)

CREDS_FILE = ROOT_DIR / "lab" / "credentials.json"
assert CREDS_FILE.exists(), "Missing lab/credentials.json"
creds = json.loads(CREDS_FILE.read_text())

TOKEN = creds["user_a"]["token"]
CANARY_VAL = creds["canary_value"]

RUNS = 3
all_metrics = []
all_c_results = []

for i in range(1, RUNS + 1):
    run_dir = RESULTS_DIR / f"run_{i}"
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}\n>>> STARTING ABLATION BENCHMARK RUN {i}/{RUNS}\n{'='*70}")

    # 1. Reset canary hits
    try:
        requests.post("http://localhost:9999/_reset", timeout=5)
        print("Canary hits reset.")
    except Exception as e:
        print(f"Warning resetting canary: {e}")

    # 2. Execute benchmark CLI command
    cmd = [
        "py", "-3.10", "-u", "cli.py", "benchmark",
        "--findings", "findings_combined.json",
        "--truth", "lab/ground_truth.json",
        "--target", "http://juiceshop:3000",
        "--model", "qwen2.5-coder:7b",
        "--token", TOKEN,
        "--canary-value", CANARY_VAL,
        "--out-dir", str(run_dir),
    ]

    subprocess.run(cmd, check=True)

    # 3. Collect run metrics
    metrics_path = run_dir / "benchmark_metrics.json"
    assert metrics_path.exists(), f"Missing {metrics_path}"
    m = json.loads(metrics_path.read_text())
    all_metrics.append(m)

    c_res_path = run_dir / "verified_findings.json"
    if c_res_path.exists():
        all_c_results.append(json.load(open(c_res_path)))

    print(
        f"Run {i} finished: Raw Prec={m['raw']['precision']*100:.1f}%, "
        f"B1 Prec={m['llm_only']['precision']*100:.1f}%, "
        f"B2 Prec={m.get('llm_cot', {}).get('precision', 0.0)*100:.1f}%, "
        f"Verifier Prec={m['verified']['precision']*100:.1f}%, "
        f"Strict FPRR={m.get('strict_FPRR_%', 0.0):.1f}%"
    )

# Aggregate across 3 runs
summary = {}
configs = ["raw", "llm_only", "llm_cot", "verified"]
labels = {
    "raw": "A: Raw Scanner",
    "llm_only": "B1: Zero-Shot LLM",
    "llm_cot": "B2: Skeptical CoT",
    "verified": "C: VeriPoC (Ours)",
}

for cfg in configs:
    p_list = [m[cfg]["precision"] * 100 for m in all_metrics if cfg in m]
    r_list = [m[cfg]["recall"] * 100 for m in all_metrics if cfg in m]
    f1_list = [m[cfg]["f1"] * 100 for m in all_metrics if cfg in m]
    conf_list = [m[cfg].get("confirmed", 0) for m in all_metrics if cfg in m]
    fp_cnt_list = [m[cfg].get("false_positive", 0) for m in all_metrics if cfg in m]
    inconc_list = [m[cfg].get("inconclusive", 0) for m in all_metrics if cfg in m]
    lat_list = [m[cfg].get("latency_per_finding", 0.0) for m in all_metrics if cfg in m]

    if cfg == "raw":
        fprr_list = [0.0] * RUNS
        strict_fprr_list = [0.0] * RUNS
    elif cfg == "llm_only":
        fprr_list = [m.get("FPRR_llm_%", 0.0) for m in all_metrics]
        strict_fprr_list = [m.get("strict_FPRR_llm_%", m.get("FPRR_llm_%", 0.0)) for m in all_metrics]
    elif cfg == "llm_cot":
        fprr_list = [m.get("FPRR_cot_%", 0.0) for m in all_metrics]
        strict_fprr_list = [m.get("strict_FPRR_cot_%", m.get("FPRR_cot_%", 0.0)) for m in all_metrics]
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
        "latency_per_finding": {"mean": float(np.mean(lat_list)), "std": float(np.std(lat_list)), "values": lat_list},
    }

# Additional Config C metrics: retry distribution & tokens
last_run_c = all_c_results[-1] if all_c_results else []
n_c = max(1, len(last_run_c))
att_counts = {1: 0, 2: 0, 3: 0}
for r in last_run_c:
    att_used = min(3, max(1, r.get("attempts", 1)))
    att_counts[att_used] += 1

retry_dist = {f"attempt_{k}": round((cnt / n_c) * 100, 1) for k, cnt in att_counts.items()}
tokens_list = [m["verified"].get("avg_tokens_per_finding", 0.0) for m in all_metrics]
summary["verified"]["retry_distribution"] = retry_dist
summary["verified"]["avg_tokens_per_finding"] = {
    "mean": float(np.mean(tokens_list)),
    "std": float(np.std(tokens_list)),
    "values": tokens_list,
}

# Aggregate Failure Mode Taxonomy across runs
taxonomy_agg = FailureModeTaxonomy.aggregate_from_results(last_run_c)
summary["failure_mode_taxonomy"] = taxonomy_agg

# Save summary JSON
summary_file = RESULTS_DIR / "ablation_summary.json"
summary_file.write_text(json.dumps(summary, indent=2))
print(f"\nSaved summary to {summary_file}")

# Copy latest triage_report.md and run_metadata.json to results/
latest_run_dir = RESULTS_DIR / f"run_{RUNS}"
if (latest_run_dir / "triage_report.md").exists():
    shutil.copy(latest_run_dir / "triage_report.md", RESULTS_DIR / "triage_report.md")
if (latest_run_dir / "run_metadata.json").exists():
    shutil.copy(latest_run_dir / "run_metadata.json", RESULTS_DIR / "run_metadata.json")

# Generate 300 DPI thesis charts in results/charts/
thesis_charts = generate_thesis_charts(summary, last_run_c, CHARTS_DIR)
for name, p in thesis_charts.items():
    print(f"Generated thesis chart: {p}")

# Print Ablation Table with Mean +/- Std and Latency
print("\n" + "=" * 115)
print(f"{'Configuration':<24} | {'Conf':<6} | {'FP':<6} | {'Inconc':<7} | {'Precision (%)':<15} | {'Recall (%)':<15} | {'Strict FPRR (%)':<15} | {'Latency (s)':<12}")
print("=" * 115)
for cfg in configs:
    s = summary[cfg]
    c_str = f"{s['confirmed']['mean']:.1f}"
    fp_str = f"{s['false_positive']['mean']:.1f}"
    inc_str = f"{s['inconclusive']['mean']:.1f}"
    p_str = f"{s['precision']['mean']:.1f} ± {s['precision']['std']:.1f}"
    r_str = f"{s['recall']['mean']:.1f} ± {s['recall']['std']:.1f}"
    f_str = f"{s['strict_fprr']['mean']:.1f} ± {s['strict_fprr']['std']:.1f}"
    lat_str = f"{s['latency_per_finding']['mean']:.2f}s"
    print(f"{s['label']:<24} | {c_str:<6} | {fp_str:<6} | {inc_str:<7} | {p_str:<15} | {r_str:<15} | {f_str:<15} | {lat_str:<12}")
print("=" * 115)

# Print Failure Mode Taxonomy Summary
print("\n" + "=" * 60)
print("             FAILURE MODE TAXONOMY (CONFIG C)")
print("=" * 60)
for cat, count in taxonomy_agg["counts"].items():
    print(f"  {cat:<28} : {count}")
print(f"  {'TOTAL INCONCLUSIVE':<28} : {taxonomy_agg['total_inconclusive']}")
print("=" * 60)

# Print Retry Distribution
print("\n" + "=" * 60)
print("             RETRY DISTRIBUTION (CONFIG C)")
print("=" * 60)
for k, v in retry_dist.items():
    print(f"  {k:<28} : {v}%")
print("=" * 60 + "\n")
