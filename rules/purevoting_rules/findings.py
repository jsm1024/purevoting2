"""Build immutable, contract-valid finding submissions for the local worker.

Implementation coverage is kept in the report and in ``summary``. It is never
smuggled into an extra field in the frozen FindingSubmission contract.
"""

from __future__ import annotations

import copy
import json
import secrets
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .hashing import canonical
from .models import RuleOutcome
from .paths import reference_root


REQUIRED_OBSERVED: dict[str, tuple[str, ...]] = {
    "R1": (
        "accepted_duplicate_tokens", "accepted_duplicate_nullifiers",
        "unknown_tokens", "unknown_nullifiers", "used_then_revoked",
        "refused_duplicates",
    ),
    "R2": (
        "events_before_start", "events_after_end", "ledger_rejected_window",
        "events_after_close_final", "refused_not_open",
    ),
    "R3": (
        "roster_active", "tokens_active", "token_used", "credentials_issued",
        "ballots_received", "ledger_token_used", "ledger_ballots",
        "ledger_rejected_voter_events", "redeemed_not_voted",
    ),
    "R4": (
        "unapproved_changes", "invalid_signatures", "duplicate_executions",
        "missing_effects", "target_mismatches", "roster_chain_breaks",
        "executed_actions", "failed_actions",
    ),
    "R5": (
        "rejected_checkpoints", "chain_state_mismatch", "governance_mismatch",
        "checkpoint_cadence_violations", "row_ledger_mismatches", "key_mismatch",
        "tables_mismatched", "sealed_hash_mismatches", "root_mismatches",
        "config_mismatch", "events_hash_mismatch", "anchors_mismatch",
        "events_unanchored",
    ),
}

_CONTRACT_BASE = "https://purevoting2.local/contracts/"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


@lru_cache(maxsize=4)
def _registry(root: Path) -> Registry:
    resources = []
    for path in sorted((root / "contracts").glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    # This registry contains local resources only. An unknown reference fails
    # rather than making a network request.
    return Registry().with_resources(resources)


def contract_validator(schema: dict[str, Any], *, filename: str) -> Draft202012Validator:
    """Resolve a frozen contract's relative references from local files only."""
    document = {"$id": _CONTRACT_BASE + filename, **copy.deepcopy(schema)}
    return Draft202012Validator(
        document,
        registry=_registry(reference_root()),
        format_checker=FormatChecker(),
    )


@lru_cache(maxsize=4)
def _submission_validator(root: Path) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": _CONTRACT_BASE + "finding.schema.json#/$defs/FindingSubmission"},
        registry=_registry(root),
        format_checker=FormatChecker(),
    )


def validate_submission(body: dict[str, Any]) -> None:
    """Validate the actual v1.0 schema and its canonical JSON constraints.

    Required rule observations are additionally checked by ``build_finding``.
    They are not added to the frozen schema: for example, an upstream valid
    NODE_UNAVAILABLE example contains only a ``nodes_reachable`` observation.
    """
    canonical(body)  # Reject floats, non-JSON values and unsupported integers.
    _submission_validator(reference_root()).validate(body)


def new_finding_id() -> str:
    """Generate a 128-bit ULID-shaped finding ID, with 80 random bits."""
    value = ((time.time_ns() // 1_000_000) << 80) | secrets.randbits(80)
    chars = ["0"] * 26
    for index in range(25, -1, -1):
        chars[index] = _CROCKFORD[value & 31]
        value >>= 5
    return "fnd_" + "".join(chars)


def build_finding(
    outcome: RuleOutcome,
    context: dict[str, Any],
    *,
    finding_id: str | None = None,
    checked_at: str | None = None,
) -> dict[str, Any]:
    """Build and validate one rule × election × committed-checkpoint result.

    The caller must first pass the scheduler's readiness gate. A context is
    evidence metadata, not proof that a checkpoint has actually been accepted.
    Evidence references are copied, deduplicated and sorted before hashing.
    """
    required = set(REQUIRED_OBSERVED[outcome.rule_id])
    missing = required - outcome.observed.keys()
    if missing:
        raise ValueError(f"{outcome.rule_id} missing required observations: {', '.join(sorted(missing))}")
    if outcome.result == "PASS" and any(outcome.observed[key] is None for key in required):
        raise ValueError("A passing finding cannot have unknown required observations")
    if outcome.coverage == "partial" and outcome.result == "PASS":
        raise ValueError("A partially implemented rule cannot return PASS")

    summary = outcome.summary
    if outcome.coverage == "partial":
        if not outcome.unimplemented_checks:
            raise ValueError("Partial rules must identify their unimplemented checks")
        if not all(name in summary for name in outcome.unimplemented_checks):
            summary += " Partial implementation; unimplemented checks: "
            summary += ", ".join(outcome.unimplemented_checks) + "."

    # Sorting canonical representations also makes notes deterministic. Do not
    # invent evidence merely to satisfy the FAIL minItems constraint.
    evidence_by_bytes = {
        canonical(ref): copy.deepcopy(ref) for ref in outcome.evidence_refs
    }
    evidence = [evidence_by_bytes[key] for key in sorted(evidence_by_bytes)]
    data_as_of = {
        "ledger_last_seq": context["ledger_last_seq"],
        "checkpoint_event_id": context["checkpoint_event_id"],
    }
    if "ledger_last_block" in context:
        data_as_of["ledger_last_block"] = context["ledger_last_block"]

    body: dict[str, Any] = {
        "finding_id": finding_id or new_finding_id(),
        "schema_version": "1",
        "rule_id": outcome.rule_id,
        "rule_version": "0.1.0",
        "election_id": context["election_id"],
        "result": outcome.result,
        "trigger": context.get("trigger", "SCHEDULED"),
        "checked_at": checked_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checkpoint": context["checkpoint"],
        "data_as_of": data_as_of,
        "observed": copy.deepcopy(outcome.observed),
        "expected": outcome.expected,
        "summary": summary,
        "evidence_refs": evidence,
    }
    if body["trigger"] == "MANUAL":
        if not context.get("run_request_id"):
            raise ValueError("A manual finding must identify its run_request_id")
        body["run_request_id"] = context["run_request_id"]
    if outcome.result != "PASS":
        body["severity"] = "HIGH" if outcome.result == "FAIL" else "MEDIUM"
    if outcome.result == "INCONCLUSIVE":
        body["inconclusive_reason"] = outcome.inconclusive_reason
    validate_submission(body)
    return body
