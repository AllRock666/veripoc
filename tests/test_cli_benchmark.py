import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from cli import app
from src.sandbox.runner import SandboxResult


def test_cli_benchmark_e2e(tmp_path):
    findings_file = tmp_path / "findings.json"
    truth_file = tmp_path / "truth.json"
    out_dir = tmp_path / "benchmark_results"

    findings = [
        {
            "source": "zap",
            "rule_id": "40018",
            "url": "http://juiceshop:3000/rest/products/search?q=1",
            "param": "q",
            "cwe": 89,
            "vuln_class": "sqli",
            "raw_evidence": {"evidence": "syntax error"},
        },
        {
            "source": "zap",
            "rule_id": "10000",
            "url": "http://juiceshop:3000/api/Users?email=a",
            "param": "email",
            "cwe": 89,
            "vuln_class": "sqli",
            "raw_evidence": {},
        },
    ]
    findings_file.write_text(json.dumps(findings))

    truth = {
        "findings": [
            {"path": "/rest/products/search", "param": "q", "cwe": 89, "is_vulnerable": True},
            {"path": "/api/Users", "param": "email", "cwe": 89, "is_vulnerable": False},
        ]
    }
    truth_file.write_text(json.dumps(truth))

    with patch("src.strategy.engine.OpenAICompatLLM.complete") as mock_complete, \
         patch("src.sandbox.runner.SandboxRunner.run") as mock_run:

        # Mock LLM completions:
        # First 2 calls: Baseline B1 triage (finding 0: Confirms, finding 1: False Positive)
        # Next 2 calls: Baseline B2 skeptical triage (finding 0: Confirms, finding 1: False Positive)
        # Next 2 calls: Strategy engine script generations for finding 0 and finding 1
        mock_complete.side_effect = [
            '{"verdict": "CONFIRMED", "reason": "SQL syntax injection evident"}',
            '{"verdict": "FALSE_POSITIVE", "reason": "Properly parameterized"}',
            '{"reasoning": "Direct SQL error indicates unparameterized query.", "verdict": "CONFIRMED", "reason": "SQL syntax injection evident"}',
            '{"reasoning": "Sequelize ORM parameterizes user registration.", "verdict": "FALSE_POSITIVE", "reason": "Properly parameterized"}',
            "```python\nprint('poc1')\n```",
            "```python\nprint('poc2')\n```",
        ]

        # Mock Sandbox executions:
        # Finding 0: returns timing delay -> CONFIRMED
        # Finding 1: returns no timing delay -> FALSE_POSITIVE
        mock_run.side_effect = [
            SandboxResult(
                exit_code=0,
                stdout=json.dumps({
                    "completed": True,
                    "baseline_ms": [100, 110],
                    "payload_ms": [3200, 3150],
                    "delay_s": 3,
                }),
                stderr="",
                duration_s=3.5,
            ),
            SandboxResult(
                exit_code=0,
                stdout=json.dumps({
                    "completed": True,
                    "baseline_ms": [100, 110],
                    "payload_ms": [105, 115],
                    "delay_s": 3,
                }),
                stderr="",
                duration_s=1.0,
            ),
        ]

        runner = CliRunner()
        result = runner.invoke(app, [
            "benchmark",
            "--findings", str(findings_file),
            "--truth", str(truth_file),
            "--out-dir", str(out_dir),
            "--canary-admin", "",
        ])

        assert result.exit_code == 0
        assert "ABLATION BENCHMARK RESULTS" in result.stdout
        assert "A: Raw Scanner" in result.stdout
        assert "B1: Zero-Shot LLM" in result.stdout
        assert "B2: Skeptical CoT" in result.stdout
        assert "C: VeriPoC (Ours)" in result.stdout

        # Verify output artifacts
        assert (out_dir / "benchmark_metrics.json").exists()
        assert (out_dir / "run_metadata.json").exists()
        assert (out_dir / "baseline_b1_triage.json").exists()
        assert (out_dir / "baseline_b2_triage.json").exists()
        assert (out_dir / "verified_findings.json").exists()
        assert (out_dir / "findings_summary.csv").exists()
        assert (out_dir / "triage_report.md").exists()
        assert (out_dir / "charts" / "ablation_metrics.png").exists()

        metrics = json.loads((out_dir / "benchmark_metrics.json").read_text())
        assert metrics["raw"]["precision"] == 0.5
        assert metrics["verified"]["precision"] == 1.0
        assert metrics["strict_FPRR_%"] == 100.0
