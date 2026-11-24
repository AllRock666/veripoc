import json
from pathlib import Path


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
            llm_verdicts: dict | None = None) -> dict:
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

    if llm_confirmed is not None:
        llm = evaluate(llm_confirmed, raw_keys, truth)        # Baseline B: LLM-only triage
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
    return res
