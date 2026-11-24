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
           max_attempts: int = 3, results: str = "results.json", verbose: bool = True):
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


@app.command()
def report(results: str = "results.json", truth: str = "lab/ground_truth.json",
           csv_out: str = "", charts_out: str = ""):
    """Precision / recall / FPRR vs ground truth with optional CSV/chart export."""
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


@app.command()
def benchmark(
    findings: str = "findings.json",
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
):
    """Run ablation benchmark comparing Configuration A (Raw), B (LLM-only), and C (PoC Verifier)."""
    from pathlib import Path
    from src.ingestion.schema import Finding
    from src.storage.db import get_session
    from src.sandbox.runner import SandboxRunner
    from src.strategy.engine import StrategyEngine, OpenAICompatLLM
    from src.orchestrator.pipeline import Orchestrator
    from src.reporting.baseline_b import LLMTriage
    from src.reporting.exporter import export_results_csv, generate_plots

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    typer.echo(f"Loading findings from {findings} and ground truth from {truth}...")
    findings_data = json.load(open(findings))
    findings_objs = [Finding(**raw) for raw in findings_data]
    ground_truth = load_ground_truth(truth)

    # 1. Configuration A: Raw Scanner Baseline
    raw_keys = {f.dedupe_key for f in findings_objs}
    typer.echo(f"Configuration A (Raw Scanner): {len(raw_keys)} alerts")

    # 2. Configuration B: LLM-Only Zero-Shot Triage (No Sandbox)
    typer.echo(f"Running Configuration B (Zero-Shot LLM Triage with {model})...")
    llm = OpenAICompatLLM(base_url, model)
    triage = LLMTriage(llm)
    b_results = triage.triage_all(findings_objs)
    llm_confirmed = {tuple(r["key"]) for r in b_results if r["verdict"] == "CONFIRMED"}

    # 3. Configuration C: PoC Verifier (LLM + Sandbox + Deterministic Oracles)
    typer.echo(f"Running Configuration C (Autonomous PoC Verifier with {model})...")
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

    verified_confirmed = {tuple(r["key"]) for r in c_results if r["verdict"] == "CONFIRMED"}
    verified_verdicts = {tuple(r["key"]): r["verdict"] for r in c_results}
    llm_verdicts = {tuple(r["key"]): r["verdict"] for r in b_results}

    # 4. Compute Ablation Metrics
    metrics = compare(
        raw_keys,
        verified_confirmed,
        ground_truth,
        llm_confirmed=llm_confirmed,
        verified_verdicts=verified_verdicts,
        llm_verdicts=llm_verdicts,
    )

    # 5. Export Files & Plots
    metrics_file = out_path / "benchmark_metrics.json"
    with open(metrics_file, "w") as f:
        json.dump(metrics, f, indent=2)

    with open(out_path / "baseline_b_triage.json", "w") as f:
        json.dump(b_results, f, indent=2)

    with open(out_path / "verified_findings.json", "w") as f:
        json.dump(c_results, f, indent=2)

    csv_file = out_path / "findings_summary.csv"
    export_results_csv(c_results, csv_file)

    charts = generate_plots(metrics, c_results, out_path)

    # 6. Print Summary Table
    typer.echo("\n" + "=" * 92)
    typer.echo("                           ABLATION BENCHMARK RESULTS")
    typer.echo("=" * 92)
    typer.echo(f"{'Configuration':<24} | {'Conf':<5} | {'FP':<5} | {'Inconc':<6} | {'Precision':<10} | {'Recall':<10} | {'Strict FPRR':<11}")
    typer.echo("-" * 92)
    raw_m, llm_m, ver_m = metrics["raw"], metrics.get("llm_only", {}), metrics["verified"]
    typer.echo(f"{'A: Raw Scanner':<24} | {raw_m.get('confirmed', len(raw_keys)):<5} | {raw_m.get('false_positive', 0):<5} | {raw_m.get('inconclusive', 0):<6} | {raw_m['precision']*100:>8.1f}% | {raw_m['recall']*100:>8.1f}% | {'0.0%':>11}")
    if llm_m:
        typer.echo(f"{'B: LLM-Only':<24} | {llm_m.get('confirmed', 0):<5} | {llm_m.get('false_positive', 0):<5} | {llm_m.get('inconclusive', 0):<6} | {llm_m['precision']*100:>8.1f}% | {llm_m['recall']*100:>8.1f}% | {metrics.get('strict_FPRR_llm_%', 0):>10.1f}%")
    typer.echo(f"{'C: PoC Verifier (Ours)':<24} | {ver_m.get('confirmed', 0):<5} | {ver_m.get('false_positive', 0):<5} | {ver_m.get('inconclusive', 0):<6} | {ver_m['precision']*100:>8.1f}% | {ver_m['recall']*100:>8.1f}% | {metrics.get('strict_FPRR_%', 0):>10.1f}%")
    typer.echo("=" * 92)
    typer.echo(f"Output files and plots written to: {out_path.resolve()}\n")



if __name__ == "__main__":
    app()
