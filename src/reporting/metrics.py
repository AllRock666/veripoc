import json
import re
from pathlib import Path
from typing import Any


def load_ground_truth(path) -> dict:
    """{(path, param, cwe): is_vulnerable}"""
    d = json.loads(Path(path).read_text())["findings"]
    return {(x["path"], x.get("param", ""), x["cwe"]): x["is_vulnerable"] for x in d}


def _prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def evaluate(predicted_positive: set, universe: set, truth: dict) -> dict:
    tp = sum(1 for k in predicted_positive if truth.get(k) is True)
    fp = sum(1 for k in predicted_positive if truth.get(k) is False)
    fn = sum(1 for k in universe if truth.get(k) is True and k not in predicted_positive)
    return _prf(tp, fp, fn)


def fprr(fp_raw: int, fp_verified: int) -> float:
    return (fp_raw - fp_verified) / fp_raw * 100 if fp_raw else 0.0


def compare(raw_keys: set, verified_confirmed: set, truth: dict,
            llm_confirmed: set | None = None,
            verified_verdicts: dict | None = None,
            llm_verdicts: dict | None = None,
            b2_confirmed: set | None = None,
            b2_verdicts: dict | None = None) -> dict:
    raw = evaluate(raw_keys, raw_keys, truth)                 # Baseline A: trust every alert
    ver = evaluate(verified_confirmed, raw_keys, truth)       # Baseline C: LLM + sandbox + oracles
    res = {"raw": raw, "verified": ver, "FPRR_%": fprr(raw["fp"], ver["fp"])}

    # Break out counts: confirmed, false_positive, inconclusive
    raw["confirmed"] = len(raw_keys)
    raw["false_positive"] = 0
    raw["inconclusive"] = 0

    raw_fp_count = raw["fp"]
    if verified_verdicts:
        ver["confirmed"] = sum(1 for v in verified_verdicts.values() if v == "CONFIRMED")
        ver["false_positive"] = sum(1 for v in verified_verdicts.values() if v == "FALSE_POSITIVE")
        ver["inconclusive"] = sum(1 for v in verified_verdicts.values() if v == "INCONCLUSIVE")
        strict_fp_eliminated = sum(1 for k, v in verified_verdicts.items() if truth.get(k) is False and v == "FALSE_POSITIVE")
        res["strict_FPRR_%"] = (strict_fp_eliminated / raw_fp_count * 100) if raw_fp_count else 0.0
    else:
        ver["confirmed"] = len(verified_confirmed)
        ver["false_positive"] = len(raw_keys) - len(verified_confirmed)
        ver["inconclusive"] = 0
        res["strict_FPRR_%"] = res["FPRR_%"]

    # Baseline B1: Zero-shot LLM triage
    if llm_confirmed is not None:
        llm = evaluate(llm_confirmed, raw_keys, truth)
        if llm_verdicts:
            llm["confirmed"] = sum(1 for v in llm_verdicts.values() if v == "CONFIRMED")
            llm["false_positive"] = sum(1 for v in llm_verdicts.values() if v == "FALSE_POSITIVE")
            llm["inconclusive"] = sum(1 for v in llm_verdicts.values() if v == "INCONCLUSIVE")
            llm_fp_eliminated = sum(1 for k, v in llm_verdicts.items() if truth.get(k) is False and v == "FALSE_POSITIVE")
            res["strict_FPRR_llm_%"] = (llm_fp_eliminated / raw_fp_count * 100) if raw_fp_count else 0.0
        else:
            llm["confirmed"] = len(llm_confirmed)
            llm["false_positive"] = len(raw_keys) - len(llm_confirmed)
            llm["inconclusive"] = 0
            res["strict_FPRR_llm_%"] = fprr(raw["fp"], llm["fp"])
        res["llm_only"] = llm
        res["FPRR_llm_%"] = fprr(raw["fp"], llm["fp"])

    # Baseline B2: Skeptical CoT LLM triage
    if b2_confirmed is not None:
        b2 = evaluate(b2_confirmed, raw_keys, truth)
        if b2_verdicts:
            b2["confirmed"] = sum(1 for v in b2_verdicts.values() if v == "CONFIRMED")
            b2["false_positive"] = sum(1 for v in b2_verdicts.values() if v == "FALSE_POSITIVE")
            b2["inconclusive"] = sum(1 for v in b2_verdicts.values() if v == "INCONCLUSIVE")
            b2_fp_eliminated = sum(1 for k, v in b2_verdicts.items() if truth.get(k) is False and v == "FALSE_POSITIVE")
            res["strict_FPRR_cot_%"] = (b2_fp_eliminated / raw_fp_count * 100) if raw_fp_count else 0.0
        else:
            b2["confirmed"] = len(b2_confirmed)
            b2["false_positive"] = len(raw_keys) - len(b2_confirmed)
            b2["inconclusive"] = 0
            res["strict_FPRR_cot_%"] = fprr(raw["fp"], b2["fp"])
        res["llm_cot"] = b2
        res["FPRR_cot_%"] = fprr(raw["fp"], b2["fp"])

    return res


class FailureModeTaxonomy:
    """Aggregates and categorizes inconclusive/failed verification attempts."""
    TIMEOUT = "TIMEOUT"
    SYNTAX_OR_RUNTIME_ERROR = "SYNTAX_OR_RUNTIME_ERROR"
    AUTH_FAILURE = "AUTH_FAILURE"
    ORACLE_UNMATCHED = "ORACLE_UNMATCHED"
    OTHER = "OTHER"

    CATEGORIES = [
        TIMEOUT,
        SYNTAX_OR_RUNTIME_ERROR,
        AUTH_FAILURE,
        ORACLE_UNMATCHED,
        OTHER,
    ]

    @classmethod
    def classify(cls, exit_code: int = 0, stdout: str = "", stderr: str = "",
                 timed_out: bool = False, reason: str = "") -> str:
        combined = f"{stderr}\n{stdout}\n{reason}".lower()

        # 1. Timeout
        if timed_out or "timed out" in combined or "timeouterror" in combined or "timeout" in reason.lower():
            return cls.TIMEOUT

        # 2. Auth Failure
        if any(k in combined for k in [
            "401", "403", "unauthorized", "forbidden", "jwt expired", "token expired",
            "auth failed", "access denied", "invalid token", "not logged in"
        ]):
            return cls.AUTH_FAILURE

        # 3. Syntax / Runtime Error
        if any(k in combined for k in [
            "syntaxerror", "indentationerror", "nameerror", "importerror",
            "modulenotfounderror", "typeerror", "attributeerror", "traceback (most recent call last)",
            "exception in thread", "fatal error"
        ]) or (exit_code != 0 and exit_code != -1):
            return cls.SYNTAX_OR_RUNTIME_ERROR

        # 4. Oracle unmatched / no telemetry
        if any(k in combined for k in [
            "no valid telemetry", "insufficient timing samples", "test did not complete",
            "oracle", "unmatched", "telemetry"
        ]) or not stdout.strip():
            return cls.ORACLE_UNMATCHED

        return cls.OTHER

    @classmethod
    def aggregate_from_results(cls, results: list[dict]) -> dict[str, Any]:
        """Aggregate from list of verified findings dictionaries."""
        counts = {cat: 0 for cat in cls.CATEGORIES}
        details = {cat: [] for cat in cls.CATEGORIES}

        for r in results:
            if r.get("verdict") == "INCONCLUSIVE":
                history = r.get("history", [])
                cat = cls.OTHER
                if history:
                    last_att = history[-1]
                    cat = cls.classify(
                        exit_code=last_att.get("exit_code", 0),
                        stdout=last_att.get("stdout", ""),
                        stderr=last_att.get("stderr", ""),
                        reason=r.get("reason", ""),
                    )
                else:
                    cat = cls.classify(reason=r.get("reason", ""))
                counts[cat] += 1
                details[cat].append({
                    "key": r.get("key"),
                    "reason": r.get("reason"),
                    "attempts": r.get("attempts", len(history)),
                })

        return {
            "counts": counts,
            "total_inconclusive": sum(counts.values()),
            "details": details,
        }

    @classmethod
    def aggregate_from_db(cls, session) -> dict[str, Any]:
        """Aggregate from verifier.db via SQLAlchemy session."""
        from ..storage.db import FindingRow, AttemptRow

        inconc_findings = session.query(FindingRow).filter_by(verdict="INCONCLUSIVE").all()
        counts = {cat: 0 for cat in cls.CATEGORIES}
        details = {cat: [] for cat in cls.CATEGORIES}

        for f in inconc_findings:
            attempts = session.query(AttemptRow).filter_by(finding_id=f.id).order_by(AttemptRow.n.asc()).all()
            if attempts:
                last_att = attempts[-1]
                cat = cls.classify(
                    exit_code=last_att.exit_code,
                    stdout=last_att.stdout or "",
                    stderr=last_att.stderr or "",
                    reason=f.reason or "",
                )
            else:
                cat = cls.classify(reason=f.reason or "")
            counts[cat] += 1
            details[cat].append({
                "dedupe_key": f.dedupe_key,
                "reason": f.reason,
                "attempt_count": len(attempts),
            })

        return {
            "counts": counts,
            "total_inconclusive": sum(counts.values()),
            "details": details,
        }
