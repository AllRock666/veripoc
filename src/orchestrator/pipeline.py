import json, requests
from dataclasses import dataclass
from ..ingestion.schema import Finding, Verdict
from ..oracles.base import OracleContext, evaluate
from ..storage.db import AttemptRow, upsert_finding


@dataclass
class Attempt:
    n: int; script: str; exit_code: int; stdout: str; stderr: str
    duration_s: float; verdict: Verdict | None = None; tokens: int = 0


def parse_telemetry(stdout: str) -> dict | None:
    for line in reversed([l for l in stdout.splitlines() if l.strip()]):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


class Orchestrator:
    def __init__(self, engine, sandbox, session, target_env: dict,
                 canary_value="", canary_admin="http://localhost:9999", max_attempts=3,
                 seed_state_path: str = "lab/seed_state.json"):
        self.engine, self.sandbox, self.session = engine, sandbox, session
        self.env = dict(target_env)
        self.canary_value, self.canary_admin = canary_value, canary_admin
        self.max_attempts = max_attempts
        self.seed_state_path = seed_state_path
        self._load_seed_state()

    def _load_seed_state(self):
        if not self.seed_state_path:
            return
        from pathlib import Path
        p = Path(self.seed_state_path)
        if p.exists():
            try:
                state = json.loads(p.read_text())
                if "victim_basket_id" in state and "VICTIM_BASKET_ID" not in self.env:
                    self.env["VICTIM_BASKET_ID"] = str(state["victim_basket_id"])
                if "victim_address_id" in state and "VICTIM_ADDRESS_ID" not in self.env:
                    self.env["VICTIM_ADDRESS_ID"] = str(state["victim_address_id"])
            except Exception:
                pass

    def _canary_hits(self):
        if not self.canary_admin:
            return []
        try:
            return requests.get(f"{self.canary_admin}/_hits", timeout=3).json()
        except Exception:
            return []

    def verify(self, f: Finding):
        row = upsert_finding(self.session, f)
        history: list[Attempt] = []
        verdict, reason = Verdict.INCONCLUSIVE, "no valid telemetry"
        for n in range(1, self.max_attempts + 1):
            tokens_before = getattr(getattr(self.engine, "llm", None), "tokens_used", 0)
            script = self.engine.generate(f, history)
            tokens_after = getattr(getattr(self.engine, "llm", None), "tokens_used", 0)
            tokens = max(0, tokens_after - tokens_before)

            try:
                res = self.sandbox.run(script, env=self.env, vuln_class=f.vuln_class)
            except TypeError:
                res = self.sandbox.run(script, env=self.env)
            a = Attempt(n, script, res.exit_code, res.stdout, res.stderr, res.duration_s, tokens=tokens)
            tel = parse_telemetry(res.stdout) if res.exit_code == 0 else None
            if tel is not None:
                ctx = OracleContext(canary_value=self.canary_value, canary_hits=self._canary_hits())
                o = evaluate(f, tel, ctx)
                a.verdict, verdict, reason = o.verdict, o.verdict, o.reason
            history.append(a)
            self.session.add(AttemptRow(finding_id=row.id, n=n, script=script, exit_code=res.exit_code,
                                        stdout=res.stdout[:4000], stderr=res.stderr[:4000],
                                        duration_s=res.duration_s, verdict=(a.verdict.value if a.verdict else None),
                                        tokens=tokens))
            self.session.commit()
            if verdict != Verdict.INCONCLUSIVE:
                break
        row.verdict, row.reason = verdict.value, reason
        self.session.commit()
        return verdict, reason, history
