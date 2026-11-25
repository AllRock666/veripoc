import csv
from pathlib import Path
from src.reporting.taxonomy import FailureMode, classify_failure, classify_finding_failure
from src.reporting.metrics import FailureModeTaxonomy, compare
from src.reporting.exporter import export_results_csv, generate_plots


def test_classify_failure():
    assert classify_failure(timed_out=True) == FailureMode.TIMEOUT
    assert classify_failure(stderr="requests.exceptions.ReadTimeout: timed out") == FailureMode.TIMEOUT
    assert classify_failure(stderr="HTTPError: 401 Client Error: Unauthorized") == FailureMode.AUTH_EXPIRY
    assert classify_failure(stdout="{\"status\": 403, \"message\": \"token expired\"}") == FailureMode.AUTH_EXPIRY
    assert classify_failure(stderr="SyntaxError: invalid syntax") == FailureMode.SYNTAX_ERROR
    assert classify_failure(stderr="ImportError: No module named requests") == FailureMode.SYNTAX_ERROR
    assert classify_failure(stdout="", stderr="") == FailureMode.NO_TELEMETRY
    assert classify_failure(stdout="{\"completed\": false}") == FailureMode.NO_TELEMETRY
    assert classify_failure(exit_code=137, stderr="Killed") == FailureMode.OTHER


def test_classify_finding_failure():
    attempts = [
        {"exit_code": 1, "stdout": "", "stderr": "SyntaxError: invalid syntax"},
        {"exit_code": 1, "stdout": "", "stderr": "401 Unauthorized for target"},
    ]
    mode = classify_finding_failure(attempts)
    assert mode == FailureMode.AUTH_EXPIRY


def test_export_results_csv(tmp_path):
    csv_file = tmp_path / "results.csv"
    data = [
        {
            "key": ["/rest/products/search", "q", 89],
            "verdict": "CONFIRMED",
            "reason": "payload slower by 3000ms",
            "attempts": 1,
            "duration_s": 3.2,
            "tokens": 450,
            "ground_truth": True,
        },
        {
            "key": ["/api/Users", "email", 89],
            "verdict": "INCONCLUSIVE",
            "reason": "test did not complete",
            "history": [{"exit_code": 1, "stdout": "", "stderr": "403 Forbidden", "duration_s": 0.5, "tokens": 200}],
            "ground_truth": False,
        },
    ]

    export_results_csv(data, csv_file)
    assert csv_file.exists()

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 2
        assert reader[0]["endpoint"] == "/rest/products/search"
        assert reader[0]["verdict"] == "CONFIRMED"
        assert reader[0]["tokens"] == "450"
        assert reader[0]["failure_mode"] == "none"

        assert reader[1]["endpoint"] == "/api/Users"
        assert reader[1]["verdict"] == "INCONCLUSIVE"
        assert reader[1]["failure_mode"] == "auth_expiry"


def test_generate_plots(tmp_path):
    out_dir = tmp_path / "charts"
    metrics = {
        "raw": {"precision": 0.5, "recall": 1.0, "f1": 0.67},
        "llm_only": {"precision": 0.6, "recall": 0.8, "f1": 0.69},
        "verified": {"precision": 1.0, "recall": 1.0, "f1": 1.0},
        "FPRR_llm_%": 20.0,
        "FPRR_%": 100.0,
    }
    findings_data = [
        {
            "key": ["/a", "q", 89],
            "verdict": "CONFIRMED",
            "duration_s": 6.5,
            "tokens": 800,
        },
        {
            "key": ["/b", "p", 79],
            "verdict": "FALSE_POSITIVE",
            "duration_s": 2.1,
            "tokens": 400,
        },
        {
            "key": ["/c", "x", 918],
            "verdict": "INCONCLUSIVE",
            "duration_s": 15.0,
            "tokens": 1200,
            "history": [{"exit_code": 1, "stdout": "", "stderr": "Connection timed out"}],
        },
    ]

    charts = generate_plots(metrics, findings_data, out_dir)
    assert "comparison" in charts
    assert "cost_vs_latency" in charts
    assert "failure_taxonomy" in charts
    for name, path in charts.items():
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0


def test_failure_mode_taxonomy():
    results = [
        {
            "key": ["/api/test1", "p", 89],
            "verdict": "INCONCLUSIVE",
            "reason": "timed out after 30s",
            "history": [{"exit_code": -1, "stdout": "", "stderr": "Execution timed out", "duration_s": 30.0}],
        },
        {
            "key": ["/api/test2", "p", 79],
            "verdict": "INCONCLUSIVE",
            "reason": "no valid telemetry",
            "history": [{"exit_code": 1, "stdout": "", "stderr": "SyntaxError: invalid syntax", "duration_s": 1.0}],
        },
        {
            "key": ["/api/test3", "p", 639],
            "verdict": "INCONCLUSIVE",
            "reason": "unauthorized 401",
            "history": [{"exit_code": 0, "stdout": "401 Unauthorized", "stderr": "", "duration_s": 0.5}],
        },
        {
            "key": ["/api/test4", "p", 89],
            "verdict": "CONFIRMED",
            "reason": "payload executed",
            "history": [{"exit_code": 0, "stdout": '{"completed": true}', "stderr": "", "duration_s": 1.0}],
        },
    ]

    agg = FailureModeTaxonomy.aggregate_from_results(results)
    assert agg["total_inconclusive"] == 3
    assert agg["counts"][FailureModeTaxonomy.TIMEOUT] == 1
    assert agg["counts"][FailureModeTaxonomy.SYNTAX_OR_RUNTIME_ERROR] == 1
    assert agg["counts"][FailureModeTaxonomy.AUTH_FAILURE] == 1


def test_compare_with_b2():
    truth = {
        ("/a", "q", 89): True,
        ("/b", "q", 89): False,
        ("/c", "p", 79): False,
    }
    raw_keys = set(truth.keys())
    ver_confirmed = {("/a", "q", 89)}
    ver_verdicts = {("/a", "q", 89): "CONFIRMED", ("/b", "q", 89): "FALSE_POSITIVE", ("/c", "p", 79): "FALSE_POSITIVE"}
    b1_confirmed = {("/a", "q", 89), ("/b", "q", 89), ("/c", "p", 79)}
    b2_confirmed = {("/a", "q", 89), ("/b", "q", 89)}
    b2_verdicts = {("/a", "q", 89): "CONFIRMED", ("/b", "q", 89): "CONFIRMED", ("/c", "p", 79): "FALSE_POSITIVE"}

    m = compare(
        raw_keys,
        ver_confirmed,
        truth,
        llm_confirmed=b1_confirmed,
        verified_verdicts=ver_verdicts,
        b2_confirmed=b2_confirmed,
        b2_verdicts=b2_verdicts,
    )
    assert m["raw"]["precision"] == 1 / 3
    assert m["verified"]["precision"] == 1.0
    assert m["strict_FPRR_%"] == 100.0
    assert "llm_cot" in m
    assert m["llm_cot"]["precision"] == 0.5
    assert m["strict_FPRR_cot_%"] == 50.0
