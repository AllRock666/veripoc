import json, typer
from src.ingestion.parsers import parse_zap, parse_nuclei, parse_semgrep_sarif, deduplicate
from src.reporting.metrics import load_ground_truth, compare

app = typer.Typer()


@app.command()
def ingest(zap: str = None, nuclei: str = None, semgrep: str = None, out: str = "findings.json"):
    """Normalize + deduplicate scanner output."""
    fs = (
        (parse_zap(zap) if zap else [])
        + (parse_nuclei(nuclei) if nuclei else [])
        + (parse_semgrep_sarif(semgrep) if semgrep else [])
    )
    fs = deduplicate(fs)
    json.dump([f.model_dump(mode="json") for f in fs], open(out, "w"), indent=2)
    typer.echo(f"{len(fs)} unique findings -> {out}")


@app.command()
def verify(findings: str = "findings.json", target: str = "http://juiceshop:3000",
           model: str = "qwen2.5-coder:7b", base_url: str = "http://localhost:11434/v1",
           token: str = "", canary_value: str = "", canary_admin: str = "http://localhost:9999",
           seed_state: str = "lab/seed_state.json",
           max_attempts: int = 3, results: str = "results.json", verbose: bool = True,
           export_md: str = ""):
    """Run the verification loop on every finding."""
    from src.ingestion.schema import Finding
    from src.storage.db import get_session
    from src.sandbox.runner import SandboxRunner
    from src.strategy.engine import StrategyEngine, OpenAICompatLLM
    from src.orchestrator.pipeline import Orchestrator
    orch = Orchestrator(StrategyEngine(OpenAICompatLLM(base_url, model)), SandboxRunner(),
                        get_session(), {"TARGET_URL": target, "AUTH_TOKEN": token,
                                        "CANARY_URL": "http://canary:9999"},
                        canary_value=canary_value, canary_admin=canary_admin,
                        seed_state_path=seed_state,
                        max_attempts=max_attempts)
    out = []
    for raw in json.load(open(findings)):
        f = Finding(**raw)
        v, why, hist = orch.verify(f)
        total_tok = sum(a.tokens for a in hist)
        total_dur = sum(a.duration_s for a in hist)
        out.append({
            "key": list(f.dedupe_key),
            "verdict": v.value,
            "reason": why,
            "attempts": len(hist),
            "tokens": total_tok,
            "duration_s": round(total_dur, 2),
            "history": [
                {
                    "n": a.n,
                    "script": a.script,
                    "exit_code": a.exit_code,
                    "stdout": a.stdout,
                    "stderr": a.stderr,
                    "duration_s": a.duration_s,
                    "tokens": a.tokens,
                    "verdict": a.verdict.value if a.verdict else None,
                }
                for a in hist
            ],
        })
        if verbose:
            typer.echo(f"\n=======================================================")
            typer.echo(f"Finding: {f.dedupe_key} ({f.vuln_class.value}) -> Final: {v.value} ({why})")
            typer.echo(f"Total Attempts: {len(hist)} | Total Tokens: {total_tok} | Total Duration: {total_dur:.2f}s")
            for a in hist:
                typer.echo(f"\n--- Attempt {a.n} ---")
                typer.echo(f"Exit Code: {a.exit_code} | Duration: {a.duration_s:.2f}s | Tokens: {a.tokens}")
                typer.echo(f"Attempt Verdict: {a.verdict.value if a.verdict else 'None'}")
                typer.echo(f"Generated Script:\n{a.script}\n")
                typer.echo(f"Stdout:\n{a.stdout.strip()}")
                if a.stderr.strip():
                    typer.echo(f"Stderr:\n{a.stderr.strip()}")
            typer.echo(f"=======================================================\n")
        else:
            typer.echo(f"{f.dedupe_key} -> {v.value} ({why})")
    json.dump(out, open(results, "w"), indent=2)

    if export_md:
        from src.reporting.export import export_markdown_triage_report
        export_markdown_triage_report(out, export_md)
        typer.echo(f"Exported triage report -> {export_md}")


@app.command()
def report(results: str = "results.json", truth: str = "lab/ground_truth.json",
           csv_out: str = "", charts_out: str = "", export_md: str = ""):
    """Precision / recall / FPRR vs ground truth with optional CSV/chart/markdown export."""
    res = json.load(open(results))
    t = load_ground_truth(truth)
    keys = {tuple(r["key"]) for r in res}
    confirmed = {tuple(r["key"]) for r in res if r["verdict"] == "CONFIRMED"}
    comp = compare(keys, confirmed, t)
    typer.echo(json.dumps(comp, indent=2))

    if csv_out:
        from src.reporting.exporter import export_results_csv
        export_results_csv(res, csv_out)
        typer.echo(f"Exported CSV -> {csv_out}")

    if charts_out:
        from src.reporting.exporter import generate_plots
        charts = generate_plots(comp, res, charts_out)
        typer.echo(f"Generated charts in {charts_out}: {list(charts.keys())}")

    if export_md:
        from src.reporting.export import export_markdown_triage_report
        export_markdown_triage_report(res, export_md, metrics=comp)
        typer.echo(f"Exported triage report -> {export_md}")


def _collect_run_metadata(model: str = "qwen2.5-coder:7b", base_url: str = "http://localhost:11434") -> dict:
    import sys, subprocess, docker, requests
    try:
        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        git_commit = "unknown"
    python_ver = sys.version.split()[0]
    try:
        docker_ver = docker.from_env().version().get("Version", "unknown")
    except Exception:
        docker_ver = "unknown"
    model_digest = "unknown"
    try:
        r = requests.get(f"{base_url.rstrip('/v1')}/api/tags", timeout=3)
        if r.status_code == 200:
            for m in r.json().get("models", []):
                if model in m.get("name", ""):
                    model_digest = m.get("digest", "unknown")
                    break
    except Exception:
        pass
    return {
        "git_commit": git_commit,
        "python_version": python_ver,
        "docker_version": docker_ver,
        "ollama_model": model,
        "ollama_digest": model_digest,
    }


@app.command()
def benchmark(
    findings: str = "findings_combined.json",
    truth: str = "lab/ground_truth.json",
    target: str = "http://juiceshop:3000",
    model: str = "qwen2.5-coder:7b",
    base_url: str = "http://localhost:11434/v1",
    token: str = "",
    canary_value: str = "",
    canary_admin: str = "http://localhost:9999",
    seed_state: str = "lab/seed_state.json",
    max_attempts: int = 3,
    out_dir: str = "results",
    export_md: str = "",
):
    """Run ablation benchmark comparing Configuration A, B1 (Zero-Shot), B2 (Skeptical CoT), and C (VeriPoC)."""
    import time
    from pathlib import Path
    from src.ingestion.schema import Finding
    from src.storage.db import get_session
    from src.sandbox.runner import SandboxRunner
    from src.strategy.engine import StrategyEngine, OpenAICompatLLM
    from src.orchestrator.pipeline import Orchestrator
    from src.reporting.baseline_b import LLMTriage, SkepticalCoTTriage
    from src.reporting.exporter import export_results_csv, generate_plots
    from src.reporting.charts import generate_thesis_charts
    from src.reporting.export import export_markdown_triage_report

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    charts_dir = out_path / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    typer.echo(f"Loading findings from {findings} and ground truth from {truth}...")
    findings_data = json.load(open(findings))
    findings_objs = [Finding(**raw) for raw in findings_data]
    ground_truth = load_ground_truth(truth)

    # 1. Configuration A: Raw Scanner Baseline
    raw_keys = {f.dedupe_key for f in findings_objs}
    typer.echo(f"Configuration A (Raw Scanner): {len(raw_keys)} alerts")

    llm = OpenAICompatLLM(base_url, model)

    # 2. Configuration B1: Zero-Shot LLM Triage
    typer.echo(f"Running Configuration B1 (Zero-Shot LLM Triage with {model})...")
    t0_b1 = time.time()
    triage_b1 = LLMTriage(llm)
    b1_results = []
    for f in findings_objs:
        v, r, tok = triage_b1.triage(f)
        b1_results.append({"key": list(f.dedupe_key), "verdict": v.value, "reason": r, "tokens": tok})
        typer.echo(f"  [B1] {f.dedupe_key} -> {v.value} ({tok} tokens)")
    dur_b1 = time.time() - t0_b1
    llm_confirmed = {tuple(r["key"]) for r in b1_results if r["verdict"] == "CONFIRMED"}
    llm_verdicts = {tuple(r["key"]): r["verdict"] for r in b1_results}

    # 3. Configuration B2: Skeptical Chain-of-Thought LLM Triage
    typer.echo(f"Running Configuration B2 (Skeptical CoT LLM Triage with {model})...")
    t0_b2 = time.time()
    triage_b2 = SkepticalCoTTriage(llm)
    b2_results = []
    for f in findings_objs:
        v, r, tok = triage_b2.triage(f)
        rec = {"key": list(f.dedupe_key), "verdict": v.value, "reason": r, "tokens": tok}
        if getattr(triage_b2, "_last_reasoning", None):
            rec["reasoning"] = triage_b2._last_reasoning
        b2_results.append(rec)
        typer.echo(f"  [B2] {f.dedupe_key} -> {v.value} ({tok} tokens)")
    dur_b2 = time.time() - t0_b2
    b2_confirmed = {tuple(r["key"]) for r in b2_results if r["verdict"] == "CONFIRMED"}
    b2_verdicts = {tuple(r["key"]): r["verdict"] for r in b2_results}

    # 4. Configuration C: PoC Verifier (LLM + Sandbox + Deterministic Oracles)
    typer.echo(f"Running Configuration C (Autonomous PoC Verifier with {model})...")
    t0_c = time.time()
    orch = Orchestrator(
        StrategyEngine(llm),
        SandboxRunner(),
        get_session(),
        {"TARGET_URL": target, "AUTH_TOKEN": token, "CANARY_URL": "http://canary:9999"},
        canary_value=canary_value,
        canary_admin=canary_admin,
        seed_state_path=seed_state,
        max_attempts=max_attempts,
    )

    c_results = []
    for f in findings_objs:
        v, why, hist = orch.verify(f)
        total_tok = sum(a.tokens for a in hist)
        total_dur = sum(a.duration_s for a in hist)
        hist_records = [
            {
                "n": a.n,
                "script": a.script,
                "exit_code": a.exit_code,
                "stdout": a.stdout,
                "stderr": a.stderr,
                "duration_s": a.duration_s,
                "tokens": a.tokens,
                "verdict": a.verdict.value if a.verdict else None,
            }
            for a in hist
        ]
        c_results.append({
            "key": list(f.dedupe_key),
            "verdict": v.value,
            "reason": why,
            "attempts": len(hist),
            "tokens": total_tok,
            "duration_s": round(total_dur, 2),
            "ground_truth": ground_truth.get(f.dedupe_key),
            "history": hist_records,
        })
        typer.echo(f"  Verified {f.dedupe_key} -> {v.value} ({total_dur:.1f}s, {total_tok} tokens)")
    dur_c = time.time() - t0_c

    verified_confirmed = {tuple(r["key"]) for r in c_results if r["verdict"] == "CONFIRMED"}
    verified_verdicts = {tuple(r["key"]): r["verdict"] for r in c_results}

    # 5. Compute Ablation Metrics
    metrics = compare(
        raw_keys,
        verified_confirmed,
        ground_truth,
        llm_confirmed=llm_confirmed,
        verified_verdicts=verified_verdicts,
        llm_verdicts=llm_verdicts,
        b2_confirmed=b2_confirmed,
        b2_verdicts=b2_verdicts,
    )

    # Compute Latency & Token stats per finding
    n_findings = max(1, len(findings_objs))
    metrics["raw"]["latency_per_finding"] = 0.01
    metrics["llm_only"]["latency_per_finding"] = round(dur_b1 / n_findings, 2)
    metrics["llm_only"]["total_duration_s"] = round(dur_b1, 2)
    metrics["llm_cot"]["latency_per_finding"] = round(dur_b2 / n_findings, 2)
    metrics["llm_cot"]["total_duration_s"] = round(dur_b2, 2)

    total_c_dur = sum(r["duration_s"] for r in c_results)
    total_c_tok = sum(r["tokens"] for r in c_results)
    metrics["verified"]["latency_per_finding"] = round(total_c_dur / n_findings, 2)
    metrics["verified"]["total_duration_s"] = round(dur_c, 2)
    metrics["verified"]["avg_tokens_per_finding"] = round(total_c_tok / n_findings, 1)

    # Retry distribution for Config C
    att_dist = {1: 0, 2: 0, 3: 0}
    for r in c_results:
        k_att = min(3, max(1, r["attempts"]))
        att_dist[k_att] += 1
    metrics["verified"]["retry_distribution"] = {
        f"attempt_{k}": round((cnt / n_findings) * 100, 1) for k, cnt in att_dist.items()
    }

    # 6. Collect Run Metadata & Export
    run_meta = _collect_run_metadata(model=model, base_url=base_url)
    with open(out_path / "run_metadata.json", "w") as f:
        json.dump(run_meta, f, indent=2)

    with open(out_path / "benchmark_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    with open(out_path / "baseline_b1_triage.json", "w") as f:
        json.dump(b1_results, f, indent=2)
    with open(out_path / "baseline_b_triage.json", "w") as f:
        json.dump(b1_results, f, indent=2)

    with open(out_path / "baseline_b2_triage.json", "w") as f:
        json.dump(b2_results, f, indent=2)

    with open(out_path / "verified_findings.json", "w") as f:
        json.dump(c_results, f, indent=2)

    csv_file = out_path / "findings_summary.csv"
    export_results_csv(c_results, csv_file)

    # Export Triage Markdown Report
    md_target = export_md if export_md else str(out_path / "triage_report.md")
    export_markdown_triage_report(c_results, md_target, run_metadata=run_meta, metrics=metrics)

    # Generate charts
    generate_plots(metrics, c_results, out_path)
    summary_for_charts = {
        "raw": {"precision": {"mean": metrics["raw"]["precision"] * 100}, "recall": {"mean": metrics["raw"]["recall"] * 100}, "strict_fprr": {"mean": 0.0}, "latency_per_finding": {"mean": 0.01}},
        "llm_only": {"precision": {"mean": metrics["llm_only"]["precision"] * 100}, "recall": {"mean": metrics["llm_only"]["recall"] * 100}, "strict_fprr": {"mean": metrics.get("strict_FPRR_llm_%", 0.0)}, "latency_per_finding": {"mean": metrics["llm_only"]["latency_per_finding"]}},
        "llm_cot": {"precision": {"mean": metrics["llm_cot"]["precision"] * 100}, "recall": {"mean": metrics["llm_cot"]["recall"] * 100}, "strict_fprr": {"mean": metrics.get("strict_FPRR_cot_%", 0.0)}, "latency_per_finding": {"mean": metrics["llm_cot"]["latency_per_finding"]}},
        "verified": {"precision": {"mean": metrics["verified"]["precision"] * 100}, "recall": {"mean": metrics["verified"]["recall"] * 100}, "strict_fprr": {"mean": metrics.get("strict_FPRR_%", 0.0)}, "latency_per_finding": {"mean": metrics["verified"]["latency_per_finding"]}},
    }
    generate_thesis_charts(summary_for_charts, c_results, charts_dir)

    # 7. Print Summary Table
    typer.echo("\n" + "=" * 98)
    typer.echo("                           ABLATION BENCHMARK RESULTS")
    typer.echo("=" * 98)
    typer.echo(f"{'Configuration':<26} | {'Conf':<5} | {'FP':<5} | {'Inconc':<6} | {'Precision':<10} | {'Recall':<10} | {'Strict FPRR':<11}")
    typer.echo("-" * 98)
    raw_m = metrics["raw"]
    b1_m = metrics.get("llm_only", {})
    b2_m = metrics.get("llm_cot", {})
    ver_m = metrics["verified"]

    typer.echo(f"{'A: Raw Scanner':<26} | {raw_m.get('confirmed', len(raw_keys)):<5} | {raw_m.get('false_positive', 0):<5} | {raw_m.get('inconclusive', 0):<6} | {raw_m['precision']*100:>8.1f}% | {raw_m['recall']*100:>8.1f}% | {'0.0%':>11}")
    if b1_m:
        typer.echo(f"{'B1: Zero-Shot LLM':<26} | {b1_m.get('confirmed', 0):<5} | {b1_m.get('false_positive', 0):<5} | {b1_m.get('inconclusive', 0):<6} | {b1_m['precision']*100:>8.1f}% | {b1_m['recall']*100:>8.1f}% | {metrics.get('strict_FPRR_llm_%', 0):>10.1f}%")
    if b2_m:
        typer.echo(f"{'B2: Skeptical CoT':<26} | {b2_m.get('confirmed', 0):<5} | {b2_m.get('false_positive', 0):<5} | {b2_m.get('inconclusive', 0):<6} | {b2_m['precision']*100:>8.1f}% | {b2_m['recall']*100:>8.1f}% | {metrics.get('strict_FPRR_cot_%', 0):>10.1f}%")
    typer.echo(f"{'C: VeriPoC (Ours)':<26} | {ver_m.get('confirmed', 0):<5} | {ver_m.get('false_positive', 0):<5} | {ver_m.get('inconclusive', 0):<6} | {ver_m['precision']*100:>8.1f}% | {ver_m['recall']*100:>8.1f}% | {metrics.get('strict_FPRR_%', 0):>10.1f}%")
    typer.echo("=" * 98)
    typer.echo(f"Output files, charts, and report written to: {out_path.resolve()}\n")



if __name__ == "__main__":
    app()
