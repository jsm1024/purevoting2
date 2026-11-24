"""Tests of pinned B1 semantics, evidence coverage, and report trust boundaries."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from purevoting_rules.audit_report import (
    build_report, load_mapping, new_report_id, required_evidence_refs,
    select_cause, validate_report,
)
from purevoting_rules.paths import reference_root


WHEN = "2026-11-24T09:00:00Z"
MAPPING_PATH = Path(__file__).resolve().parents[1] / "config" / "b1-cause-map.pr10.json"


def finding(rule="R5", result="FAIL", observed=None, reason=None):
    path = reference_root() / "contracts/examples/valid/finding.FindingSubmission/r3_fail.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value.update(rule_id=rule, result=result, observed=observed or {"sealed_hash_mismatches": 1})
    value["summary"] = "Example finding."
    if result == "INCONCLUSIVE":
        value["inconclusive_reason"] = reason or "OTHER"
    return value


def report_for(value, **kwargs):
    args = {
        "verified_refs": required_evidence_refs(value),
        "tool_calls": [{"tool": "get_finding", "called_at": WHEN, "ok": True, "result_count": 1}],
        "mapping": load_mapping(), "allow_proposed_mapping": True,
        "created_at": WHEN,
    }
    args.update(kwargs)
    return build_report(value, **args)


@pytest.mark.parametrize("rule,observed,cause", [
    ("R1", {"accepted_duplicate_tokens": 1, "unknown_tokens": 1}, "PROCESSING_BUG"),
    ("R1", {"unknown_tokens": 1}, "DATA_TAMPERING"),
    ("R1", {"unknown_nullifiers": 1}, "DATA_TAMPERING"),
    ("R2", {"events_after_close_final": 1}, "PROCESSING_BUG"),
    ("R2", {"ledger_rejected_window": 1}, "PROCESSING_BUG"),
    ("R3", {"tally_count_mismatches": 1, "count_relationship_violations": ["tally_counts", "committed_counts"]}, "DATA_TAMPERING"),
    ("R3", {"count_relationship_violations": ["checkpoint_voter_events"]}, "PROCESSING_BUG"),
    ("R4", {"roster_chain_breaks": 1, "missing_effects": 2}, "UNAUTHORIZED_ADMIN_ACTION"),
    ("R4", {"missing_effects": 1}, "PROCESSING_BUG"),
    ("R5", {"tables_mismatched": 1, "config_mismatch": 1}, "DATA_TAMPERING"),
    ("R5", {"chain_state_mismatch": 1}, "DATA_TAMPERING"),
    ("R5", {"governance_mismatch": 1}, "DATA_TAMPERING"),
    ("R5", {"tally_root_mismatches": 1}, "DATA_TAMPERING"),
    ("R5", {"tally_final_checkpoint_mismatches": 1}, "DATA_TAMPERING"),
    ("R5", {"tally_result_hash_mismatches": 1}, "DATA_TAMPERING"),
    ("R5", {"tally_invalid_set_mismatches": 1}, "DATA_TAMPERING"),
    ("R5", {"tally_share_failures": 1}, "DATA_TAMPERING"),
    ("R5", {"tally_result_mismatches": 1}, "DATA_TAMPERING"),
    ("R5", {"config_mismatch": 1, "rejected_checkpoints": 1}, "CONFIG_ERROR"),
    ("R5", {"rejected_checkpoints": 1}, "PROCESSING_BUG"),
    ("R5", {"checkpoint_cadence_violations": 1}, "PROCESSING_BUG"),
])
def test_pinned_mapping_matches_harits_order(rule, observed, cause):
    value = finding(rule=rule, observed=observed)
    match = select_cause(value, load_mapping(), allow_proposed_mapping=True)
    assert match.cause_code == cause
    report = report_for(value)
    assert report["status"] == "COMPLETED"
    assert report["hypotheses"][0]["cause_code"] == cause
    validate_report(report)


@pytest.mark.parametrize("rule,observed", [
    ("R1", {"refused_duplicates": 12}),
    ("R2", {"refused_not_open": 12}),
    ("R3", {"ballots_received": 12, "tally_ballot_count": 12, "tally_invalid_ballots": 1}),
    ("R3", {"count_relationship_violations": ["tally_counts"], "tally_count_mismatches": 0}),
    ("R4", {"executed_actions": 12, "failed_actions": 1}),
    ("R5", {"events_unanchored": 12, "rejections_unanchored": 3, "chain_anchor_ids_missing_from_gateway": ["irrelevant"]}),
    ("R5", {"unrecognized_counter": 12}),
])
def test_nondeciding_observations_never_invent_a_cause(rule, observed):
    report = report_for(finding(rule=rule, observed=observed))
    assert report["status"] == "ESCALATED"
    assert report["hypotheses"] == []


@pytest.mark.parametrize("value", [0, -1, True, False, "1", [1], {}, None])
def test_only_positive_integer_counters_match(value):
    match = select_cause(finding(observed={"sealed_hash_mismatches": value}), load_mapping(), allow_proposed_mapping=True)
    assert match is None


@pytest.mark.parametrize("reason,cause", [
    ("BATCH_NOT_ANCHORED", "LEDGER_SYNC_DELAY"),
    ("NODE_UNAVAILABLE", "SYSTEM_FAILURE"),
    ("VIEW_UNAVAILABLE", "SYSTEM_FAILURE"),
    ("KEY_NOT_REVEALED", "CONFIG_ERROR"),
    ("OTHER", None),
])
def test_inconclusive_maps_reason_without_using_failure_observations(reason, cause):
    value = finding(result="INCONCLUSIVE", observed={"sealed_hash_mismatches": 1}, reason=reason)
    report = report_for(value)
    assert report["status"] == ("COMPLETED" if cause else "ESCALATED")
    assert ([h["cause_code"] for h in report["hypotheses"]] == ([cause] if cause else []))


def test_candidate_requires_explicit_opt_in_and_discloses_provenance():
    value = finding()
    mapping = load_mapping()
    assert mapping.status == "proposed"
    assert mapping.source_commit == "4e398deb7da0256d849ab0e58bd7ac752f8db2f0"
    assert select_cause(value, mapping) is None
    report = report_for(value, allow_proposed_mapping=False)
    assert report["status"] == "ESCALATED"
    assert not report["hypotheses"]
    assert "not enabled" in report["limitations"]
    opted = report_for(value)
    assert "explicit operator opt-in" in opted["limitations"]
    assert "acceptance of the final evaluation baseline remains pending" in opted["limitations"]
    assert mapping.source_commit in opted["limitations"]
    assert opted["model"] == {"provider": "none", "name": "template", "prompt_version": "1.0.0"}
    assert "input_tokens" not in opted["trace"]


@pytest.mark.parametrize("value", ["false", "true", 1, 0, None, []])
def test_proposed_mapping_opt_in_cannot_use_python_truthiness(value):
    with pytest.raises(ValueError, match="explicit boolean"):
        select_cause(finding(), load_mapping(), allow_proposed_mapping=value)
    with pytest.raises(ValueError, match="explicit boolean"):
        report_for(finding(), allow_proposed_mapping=value)


def test_missing_own_evidence_cannot_produce_completed_report():
    value = finding()
    report = report_for(value, verified_refs=[{"kind": "finding", "ref": value["finding_id"]}])
    assert report["status"] == "ABORTED"
    assert report["abort_reason"] == "TOOL_ERROR"
    assert not report["hypotheses"]
    validate_report(report)


def test_finding_itself_must_be_verified_too():
    value = finding()
    report = report_for(value, verified_refs=value["evidence_refs"])
    assert report["status"] == "ABORTED"
    assert report["abort_reason"] == "TOOL_ERROR"


def test_own_refs_are_deduplicated_and_unrelated_refs_not_cited():
    value = finding()
    value["evidence_refs"].append(copy.deepcopy(value["evidence_refs"][0]))
    required = required_evidence_refs(value)
    unrelated = {"kind": "snapshot", "ref": "roster@999"}
    report = report_for(value, verified_refs=[*required, unrelated])
    assert report["hypotheses"][0]["evidence_refs"] == required
    assert unrelated not in report["hypotheses"][0]["evidence_refs"]


def test_untrusted_text_and_trace_arguments_are_not_report_prose():
    value = finding()
    marker = "secret-marker-token-do-not-copy"
    value["summary"] = marker
    value["expected"] = marker
    value["observed"]["unsafe_payload"] = marker
    value["evidence_refs"][0]["note"] = marker
    calls = [{"tool": "get_finding", "called_at": WHEN, "ok": True, "args": {"key": marker}, "response": marker}]
    report = report_for(value, tool_calls=calls)
    assert marker not in json.dumps(report)
    assert "args" not in report["trace"]["tool_calls"][0]
    assert all("note" not in ref for ref in report["hypotheses"][0]["evidence_refs"])


@pytest.mark.parametrize("reason", ["STEP_LIMIT", "TIMEOUT", "TOOL_ERROR"])
def test_failure_states_keep_schema_valid_abort_reason(reason):
    report = report_for(finding(), abort_reason=reason)
    assert report["status"] == "ABORTED"
    assert report["abort_reason"] == reason
    assert not report["hypotheses"]
    validate_report(report)


def test_failed_tool_trace_forces_abort():
    report = report_for(finding(), tool_calls=[{"tool": "get_finding", "called_at": WHEN, "ok": False}])
    assert report["status"] == "ABORTED"


def test_trace_cannot_overrun_budget_or_include_write_tool():
    call = {"tool": "get_finding", "called_at": WHEN, "ok": True}
    with pytest.raises(ValueError, match="20"):
        report_for(finding(), tool_calls=[call] * 21)
    with pytest.raises(ValueError, match="read-only"):
        report_for(finding(), tool_calls=[{**call, "tool": "submit_report"}])


def test_no_pass_report_and_no_human_review_field():
    assert select_cause(finding(result="PASS"), load_mapping(), allow_proposed_mapping=True) is None
    with pytest.raises(ValueError, match="Only FAIL"):
        report_for(finding(result="PASS"))
    report = report_for(finding())
    report["human_review"] = {"status": "PENDING"}
    with pytest.raises(ValidationError):
        validate_report(report)


def test_stored_finding_is_valid_input():
    path = reference_root() / "contracts/examples/valid/finding/r3_fail_pending.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["observed"]["count_relationship_violations"] = ["committed_counts"]
    report = report_for(value)
    assert report["status"] == "COMPLETED"


def test_invalid_extra_finding_fields_are_rejected():
    value = finding()
    value["invented_extra"] = "invalid"
    with pytest.raises(ValidationError):
        report_for(value)


def test_report_ids_are_schema_valid_and_new_reports_have_distinct_ids():
    value = finding()
    assert report_for(value)["report_id"] != report_for(value)["report_id"]
    assert new_report_id() != new_report_id()
    assert new_report_id(value["finding_id"]) == new_report_id(value["finding_id"])
    report = report_for(value, report_id=new_report_id())
    validate_report(report)


def write_map(tmp_path, raw):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    return path


def test_approved_mapping_requires_matching_commit_provenance(tmp_path):
    raw = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    raw["status"] = "approved"
    with pytest.raises(ValueError):
        load_mapping(write_map(tmp_path, raw))
    raw["approval"] = {"source_commit": "0" * 40, "reference": "https://github.com/jsm1024/purevoting2/pull/10#review-1"}
    with pytest.raises(ValueError, match="another source commit"):
        load_mapping(write_map(tmp_path, raw))
    raw["approval"]["source_commit"] = raw["source"]["commit"]
    mapping = load_mapping(write_map(tmp_path, raw))
    report = report_for(finding(), mapping=mapping, allow_proposed_mapping=False)
    assert report["status"] == "COMPLETED"
    assert "operator-supplied provenance, not independently verified approval" in report["limitations"]


@pytest.mark.parametrize("mutation", [
    lambda raw: raw.update(status="final"),
    lambda raw: raw["source"].update(commit="4e398de"),
    lambda raw: raw["source"].update(url="https://example.com/?token=secret"),
    lambda raw: raw["source"].update(path="../outside.md"),
    lambda raw: raw["rows"][0].update(cause_code="INVENTED_CAUSE"),
    lambda raw: raw["rows"][0].update(keys=[]),
    lambda raw: raw["rows"][0].update(match="eval"),
    lambda raw: raw["rows"][0].update(unexpected="field"),
])
def test_invalid_mapping_fails_closed(tmp_path, mutation):
    raw = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    mutation(raw)
    with pytest.raises(ValueError):
        load_mapping(write_map(tmp_path, raw))


def test_mapping_fingerprint_covers_order_and_status(tmp_path):
    raw = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    original = load_mapping()
    raw["rows"][0], raw["rows"][1] = raw["rows"][1], raw["rows"][0]
    changed = load_mapping(write_map(tmp_path, raw))
    assert changed.fingerprint != original.fingerprint
    assert original.provenance["sha256"] == original.fingerprint
    provenance = original.provenance
    provenance["status"] = "approved"
    assert original.status == "proposed"
