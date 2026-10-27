"""Checkpoint-readiness decision, without a pretend live polling service."""

from __future__ import annotations

import math


def run_decision(
    checkpoint_accepted: bool,
    gateway_available: bool,
    all_anchored: bool,
    elapsed_seconds: float,
    batch_interval_seconds: int = 60,
) -> dict[str, bool | str | None]:
    """Apply the frozen readiness gate for one discovered checkpoint.

    Elapsed time starts when CHECKPOINT_COMMITTED is accepted. At the deadline
    only anchor-dependent checks become INCONCLUSIVE; the other rules can run
    against already-read evidence. An alert decision creates no finding.

    This is a pure decision function. Election discovery, authenticated polling,
    alert delivery, input fetching and direct-chain fallback are integration work.
    """
    if any(type(value) is not bool for value in (checkpoint_accepted, gateway_available, all_anchored)):
        raise TypeError("Readiness flags must be booleans")
    if isinstance(elapsed_seconds, bool) or not isinstance(elapsed_seconds, (int, float)):
        raise TypeError("Elapsed time must be a finite number of seconds")
    if not math.isfinite(elapsed_seconds) or elapsed_seconds < 0:
        raise ValueError("Elapsed time must be finite and nonnegative")
    if type(batch_interval_seconds) is not int or batch_interval_seconds <= 0:
        raise ValueError("The anchor batch interval must be a positive integer")
    if not gateway_available:
        return {"run": False, "alert": "LEDGER_UNAVAILABLE", "anchor_timeout": False}
    if not checkpoint_accepted:
        return {"run": False, "alert": "AUDIT_DELAYED", "anchor_timeout": False}
    if all_anchored:
        return {"run": True, "alert": None, "anchor_timeout": False}
    if elapsed_seconds >= 2 * batch_interval_seconds + 60:
        return {"run": True, "alert": None, "anchor_timeout": True}
    return {"run": False, "alert": "AUDIT_DELAYED", "anchor_timeout": False}
