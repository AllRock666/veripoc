"""Taxonomy of INCONCLUSIVE verification failure modes."""
from __future__ import annotations
from enum import Enum


class FailureMode(str, Enum):
    AUTH_EXPIRY = "auth_expiry"
    SYNTAX_ERROR = "syntax_error"
    TIMEOUT = "timeout"
    NO_TELEMETRY = "no_telemetry"
    OTHER = "other"


def classify_failure(
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
    reason: str = "",
) -> FailureMode:
    """Classify an individual execution failure into the taxonomy."""
    combined = f"{stderr}\n{stdout}\n{reason}".lower()

    if timed_out or "timed out" in combined or "timeouterror" in combined or "timeout" in reason.lower():
        return FailureMode.TIMEOUT

    # Auth expiry / permission failures
    if any(k in combined for k in [
        "401", "403", "unauthorized", "forbidden", "jwt expired", "token expired",
        "auth failed", "access denied", "invalid token"
    ]):
        return FailureMode.AUTH_EXPIRY

    # Syntax / language / import errors
    if any(k in combined for k in [
        "syntaxerror", "indentationerror", "nameerror", "importerror",
        "modulenotfounderror", "typeerror", "attributeerror", "traceback (most recent call last)"
    ]):
        return FailureMode.SYNTAX_ERROR

    # Non-zero exit with no specific syntax/auth/timeout is OTHER
    if exit_code != 0:
        return FailureMode.OTHER

    # Zero exit code, but telemetry absent or incomplete
    if (
        "no valid telemetry" in combined
        or "insufficient timing samples" in combined
        or "test did not complete" in combined
        or not stdout.strip()
    ):
        return FailureMode.NO_TELEMETRY

    return FailureMode.NO_TELEMETRY


def classify_finding_failure(attempts: list) -> FailureMode:
    """Classify the failure mode of an INCONCLUSIVE finding across its attempts."""
    if not attempts:
        return FailureMode.OTHER

    def get_val(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    for att in reversed(attempts):
        code = get_val(att, "exit_code", 0)
        out = get_val(att, "stdout", "")
        err = get_val(att, "stderr", "")
        mode = classify_failure(exit_code=code, stdout=out, stderr=err)
        if mode != FailureMode.NO_TELEMETRY:
            return mode

    last = attempts[-1]
    return classify_failure(
        exit_code=get_val(last, "exit_code", 0),
        stdout=get_val(last, "stdout", ""),
        stderr=get_val(last, "stderr", ""),
    )
