import json
import pytest
from src.ingestion.schema import Finding, VulnClass, Verdict
from src.sandbox.runner import SandboxResult
from src.strategy.engine import StrategyEngine
from src.orchestrator.pipeline import Orchestrator
from src.storage.db import get_session, FindingRow, AttemptRow


class MockLLM:
    """Returns canned responses or a sequence of responses."""
    def __init__(self, responses: list[str] | None = None):
        self.responses = list(responses or ["```python\nprint('canned')\n```"])
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


class FakeSandbox:
    """Returns canned SandboxResults, either fixed or sequentially."""
    def __init__(self, results: list[SandboxResult] | None = None):
        self.results = list(results or [SandboxResult(0, '{"completed": true}', "", 0.1)])
        self.runs: list[tuple[str, dict | None]] = []

    def run(self, script: str, env: dict | None = None) -> SandboxResult:
        self.runs.append((script, env))
        if len(self.results) > 1:
            return self.results.pop(0)
        return self.results[0]


@pytest.fixture
def db_session():
    return get_session("sqlite:///:memory:")


def test_retry_on_crash(db_session):
    """Test retry when script crashes on first attempt, then succeeds."""
    finding = Finding(
        source="zap",
        rule_id="40018",
        url="http://target/rest/products/search?q=1",
        param="q",
        cwe=89,
        vuln_class=VulnClass.SQLI,
    )
    llm = MockLLM(["```python\n# attempt 1\n```", "```python\n# attempt 2\n```"])
    sandbox = FakeSandbox([
        SandboxResult(exit_code=1, stdout="", stderr="SyntaxError: invalid syntax", duration_s=0.2),
        SandboxResult(
            exit_code=0,
            stdout=json.dumps({
                "completed": True,
                "baseline_ms": [100, 110],
                "payload_ms": [3200, 3150],
                "delay_s": 3,
            }),
            stderr="",
            duration_s=6.5,
        ),
    ])
    orch = Orchestrator(
        engine=StrategyEngine(llm),
        sandbox=sandbox,
        session=db_session,
        target_env={"TARGET_URL": "http://target"},
        canary_admin="",
        max_attempts=3,
    )

    verdict, reason, history = orch.verify(finding)

    assert verdict == Verdict.CONFIRMED
    assert "slower" in reason
    assert len(history) == 2
    assert len(sandbox.runs) == 2
    assert history[0].exit_code == 1
    assert history[0].verdict is None
    assert history[1].exit_code == 0
    assert history[1].verdict == Verdict.CONFIRMED

    # Check database persistence
    rows = db_session.query(FindingRow).all()
    assert len(rows) == 1
    assert rows[0].verdict == Verdict.CONFIRMED.value

    attempts = db_session.query(AttemptRow).filter_by(finding_id=rows[0].id).all()
    assert len(attempts) == 2
    assert attempts[0].n == 1 and attempts[0].exit_code == 1
    assert attempts[1].n == 2 and attempts[1].exit_code == 0


def test_stop_on_decisive_verdict(db_session):
    """Test stopping immediately when attempt 1 yields a decisive FALSE_POSITIVE."""
    finding = Finding(
        source="zap",
        rule_id="40018",
        url="http://target/rest/products/search?q=1",
        param="q",
        cwe=89,
        vuln_class=VulnClass.SQLI,
    )
    llm = MockLLM(["```python\n# attempt 1\n```"])
    sandbox = FakeSandbox([
        SandboxResult(
            exit_code=0,
            stdout=json.dumps({
                "completed": True,
                "baseline_ms": [100, 110],
                "payload_ms": [105, 112],
                "delay_s": 3,
            }),
            stderr="",
            duration_s=1.0,
        )
    ])
    orch = Orchestrator(
        engine=StrategyEngine(llm),
        sandbox=sandbox,
        session=db_session,
        target_env={"TARGET_URL": "http://target"},
        canary_admin="",
        max_attempts=3,
    )

    verdict, reason, history = orch.verify(finding)

    assert verdict == Verdict.FALSE_POSITIVE
    assert "no timing delta" in reason
    assert len(history) == 1
    assert len(sandbox.runs) == 1

    rows = db_session.query(FindingRow).all()
    assert rows[0].verdict == Verdict.FALSE_POSITIVE.value
    attempts = db_session.query(AttemptRow).filter_by(finding_id=rows[0].id).all()
    assert len(attempts) == 1


def test_inconclusive_after_max_attempts(db_session):
    """Test that after max_attempts failing, the final verdict is INCONCLUSIVE."""
    finding = Finding(
        source="nuclei",
        rule_id="ssrf-test",
        url="http://target/fetch",
        param="url",
        cwe=918,
        vuln_class=VulnClass.SSRF,
    )
    llm = MockLLM(["```python\n# attempt\n```"])
    sandbox = FakeSandbox([
        SandboxResult(exit_code=1, stdout="", stderr="Connection timed out", duration_s=10.0, timed_out=True),
        SandboxResult(exit_code=1, stdout="", stderr="Connection timed out", duration_s=10.0, timed_out=True),
        SandboxResult(exit_code=0, stdout=json.dumps({"completed": False}), stderr="", duration_s=1.0),
    ])
    orch = Orchestrator(
        engine=StrategyEngine(llm),
        sandbox=sandbox,
        session=db_session,
        target_env={"TARGET_URL": "http://target"},
        canary_admin="",
        max_attempts=3,
    )

    verdict, reason, history = orch.verify(finding)

    assert verdict == Verdict.INCONCLUSIVE
    assert len(history) == 3
    assert len(sandbox.runs) == 3

    rows = db_session.query(FindingRow).all()
    assert rows[0].verdict == Verdict.INCONCLUSIVE.value
    attempts = db_session.query(AttemptRow).filter_by(finding_id=rows[0].id).all()
    assert len(attempts) == 3


def test_orchestrator_loads_seed_state(tmp_path, db_session):
    state_file = tmp_path / "seed_state.json"
    state_file.write_text(json.dumps({"victim_basket_id": "99", "victim_address_id": "88"}))
    orch = Orchestrator(
        StrategyEngine(MockLLM()),
        FakeSandbox(),
        db_session,
        {"TARGET_URL": "http://test"},
        seed_state_path=str(state_file),
    )
    assert orch.env["VICTIM_BASKET_ID"] == "99"
    assert orch.env["VICTIM_ADDRESS_ID"] == "88"
