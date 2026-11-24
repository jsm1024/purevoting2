"""Synthetic collector/evaluator checks; these fixtures are not scenario labels."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import httpx
import pytest

from purevoting_rules.hashing import Hc
from purevoting_rules.paths import reference_root

DEVTOOLS = reference_root() / "rules/devtools"
sys.path.insert(0, str(DEVTOOLS))
from collect_rule_evidence import (ReadError, ReadOnlyServices, collect_bundle, committed_label,
                                   frozen_mapping, reduce_findings, safe_base_url)
from evaluate_rule_runs import evaluate_bundle, evaluate_many

ELECTION = "elc_" + "1" * 26
CP_EVENT = "evt_" + "2" * 26
COMMIT = "a" * 40
START = "2026-11-24T00:00:00Z"
CAPTURE = "2026-11-24T00:30:00Z"


def label_metadata(expected=None):
    expected = expected or {rule: "PASS" for rule in ("R1", "R2", "R3", "R4", "R5")}
    body = {"scenario": "T05-db-add", "rules": expected,
            "observed_nonzero": {"R4": ["roster_chain_breaks"]} if expected["R4"] == "FAIL" else {},
            "cause_code": "DATA_TAMPERING"}
    raw = json.dumps(body, sort_keys=True)
    return {"available": True, "commit": COMMIT, "commit_time": "2026-11-01T00:00:00Z",
            "precommitted": True, "path": "tests/scenarios/T05-db-add/expected.json",
            "sha256": hashlib.sha256(raw.encode()).hexdigest(), "content_utf8": raw, "body": body}


def raw_finding(index, result="PASS", *, checked_at="2026-11-24T00:10:00Z", observed=None):
    base = reference_root() / "contracts/examples/valid"
    finding = json.loads((base / "finding/r1_pass.json").read_text(encoding="utf-8"))
    finding.update({"finding_id": "fnd_" + str(index) * 26, "rule_id": "R" + str(index),
                    "election_id": ELECTION, "checkpoint": 2, "result": result, "checked_at": checked_at,
                    "recorded_event_id": "evt_" + str(index + 2) * 26,
                    "observed": observed if observed is not None else {"roster_chain_breaks": int(result == "FAIL"), "private_key": "DO-NOT-SAVE-THIS"},
                    "evidence_refs": [{"kind": "ledger_event", "ref": "evr_" + "9" * 26}]})
    finding["data_as_of"]["checkpoint_event_id"] = CP_EVENT
    finding["review"] = {"status": "NOT_REQUIRED" if result == "PASS" else "PENDING", "reviews": []}
    if result != "PASS":
        finding["severity"] = "HIGH"
    if result == "INCONCLUSIVE":
        finding["inconclusive_reason"] = "NODE_UNAVAILABLE"
    submission = {k: v for k, v in finding.items() if k not in {"review", "recorded_event_id", "evidence_check"}}
    event = json.loads((base / "ledger-events/finding_recorded.json").read_text(encoding="utf-8"))
    event.update({"event_id": finding["recorded_event_id"], "election_id": ELECTION})
    event["payload"].update({"finding_id": finding["finding_id"], "rule_id": finding["rule_id"],
                             "result": result, "finding_checkpoint": 2, "finding_hash": Hc(submission)})
    event["payload_hash"] = Hc(event["payload"])
    record = {"finding_id": finding["finding_id"], "recorded": event, "reviews": [],
              "contract_status": "NOT_REQUIRED" if result == "PASS" else "PENDING"}
    return finding, record


def mapping_repository(tmp_path, *, source_time="2020-01-01T00:00:00Z", encoding_time="2020-01-02T00:00:00Z", status="approved", encoding_newline=None):
    """Isolated synthetic approval provenance; never an approval of project PR10."""
    def git(*args, date=source_time):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True,
            env=os.environ | {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}).stdout
    git("init", "-q")
    git("config", "user.name", "Unit test")
    git("config", "user.email", "unit@example.invalid")
    source = tmp_path / "docs/test-plan.md"
    source.parent.mkdir()
    source.write_text("Synthetic mapping source for unit tests only.\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "Synthetic mapping source")
    source_commit = git("rev-parse", "HEAD").decode().strip()
    manifest = json.loads((reference_root() / "rules/config/b1-cause-map.pr10.json").read_text(encoding="utf-8"))
    manifest["status"] = status
    manifest["source"]["commit"] = source_commit
    manifest["source"]["url"] = "https://example.invalid/unit-test-source"
    if status == "approved":
        manifest["approval"] = {"source_commit": source_commit, "reference": "https://example.invalid/unit-test-approval"}
    path = tmp_path / "rules/config/unit-test-map.json"
    path.parent.mkdir(parents=True)
    raw = json.dumps(manifest, indent=2) + "\n"
    if encoding_newline is None:
        path.write_text(raw, encoding="utf-8")
    else:
        # Preserve the requested blob bytes regardless of the host's Git EOL
        # settings. The test then changes only the working-tree representation.
        (tmp_path / ".gitattributes").write_bytes(b"*.json -text\n")
        path.write_bytes(raw.encode("utf-8").replace(b"\n", encoding_newline))
    git("add", ".")
    git("commit", "-qm", "Synthetic mapping encoding", date=encoding_time)
    commit = git("rev-parse", "HEAD").decode().strip()
    return path, commit, manifest


def with_mapping(bundle, mapping, provenance, *, observations=None):
    pairs = [raw_finding(index, row["result"], observed=(observations or {}).get(row["rule_id"]))
             for index, row in enumerate(bundle["findings"], start=1)]
    decisions, invalid = reduce_findings([p[0] for p in pairs], [p[1] for p in pairs], election_id=ELECTION,
        checkpoint=2, checkpoint_event_id=CP_EVENT, observed_keys={"roster_chain_breaks"}, mapping=mapping)
    assert invalid == 0
    bundle["findings"] = decisions
    bundle["provenance"]["b1_mapping"] = provenance
    return bundle


def fixture_bundle(results=None, *, source="mock", run_id="fixture-1"):
    results = results or {rule: "PASS" for rule in ("R1", "R2", "R3", "R4", "R5")}
    pairs = [raw_finding(i, results["R" + str(i)]) for i in range(1, 6)]
    decisions, invalid = reduce_findings([p[0] for p in pairs], [p[1] for p in pairs],
        election_id=ELECTION, checkpoint=2, checkpoint_event_id=CP_EVENT, observed_keys={"roster_chain_breaks"})
    assert invalid == 0
    return {"format": "purevoting-rule-run/1", "collected_at": CAPTURE,
            "run": {"run_id": run_id, "scenario": "T05-db-add", "seed": 1, "configuration": "demo",
                    "source_mode": source, "declared_deployment_commit": COMMIT,
                    "election_id": ELECTION, "judged_checkpoint": 2, "started_at": START},
            "provenance": {"label": label_metadata(results), "independent_chain_verification": False},
            "collection": {"complete": True, "errors": []},
            "election": {"election_id": ELECTION, "status": "TALLIED"},
            "checkpoint": {"checkpoint": 2, "event_id": CP_EVENT, "ledger_status": "ACCEPTED", "reason": "TALLY"},
            "findings": decisions,
            "end_to_end": {"finalization_transaction": "NOT_VERIFIED", "finalization_refusal": "NOT_VERIFIED"}}


def test_reduced_export_drops_raw_refs_and_key_material_and_checks_body():
    finding, record = raw_finding(1)
    decisions, invalid = reduce_findings([finding], [record], election_id=ELECTION,
        checkpoint=2, checkpoint_event_id=CP_EVENT, observed_keys=set())
    assert invalid == 0 and decisions[0]["binding"]["matched"] is True
    exported = json.dumps(decisions)
    assert "evr_" not in exported and "DO-NOT-SAVE-THIS" not in exported and "private_key" not in exported
    assert decisions[0]["binding"]["signature_verified"] is False
    tampered = deepcopy(finding)
    tampered["summary"] += " changed"
    bad, invalid = reduce_findings([tampered], [record], election_id=ELECTION,
        checkpoint=2, checkpoint_event_id=CP_EVENT, observed_keys=set())
    assert invalid == 0 and bad[0]["binding"]["status"] == "RECORD_MISMATCH"


def test_gateway_record_for_another_election_is_never_bound():
    finding, record = raw_finding(1)
    record["recorded"]["election_id"] = "elc_" + "8" * 26
    decisions, invalid = reduce_findings([finding], [record], election_id=ELECTION,
        checkpoint=2, checkpoint_event_id=CP_EVENT, observed_keys=set())
    assert invalid == 0 and decisions[0]["binding"]["matched"] is False


def test_missing_decision_is_not_a_pass_or_a_full_metric():
    bundle = fixture_bundle()
    bundle["findings"] = bundle["findings"][:-1]
    result = evaluate_bundle(bundle)
    assert result["status"] == "INCOMPLETE" and result["metrics"] is None
    assert result["rules"][-1]["actual"] is None
    assert result["rules"][-1]["measurement_status"] == "NOT_EVALUATED"


def test_zero_denominator_metrics_remain_null():
    result = evaluate_bundle(fixture_bundle())
    assert result["status"] == "COMPLETE" and result["matches_label"] is True
    assert result["metrics"]["fail_precision"] is None
    assert result["metrics"]["fail_recall"] is None
    assert result["metrics"]["fail_false_positive_rate"] == 0
    assert result["root_cause_accuracy"] is None and result["official_scenario_verified"] is False


def test_inconclusive_is_preserved_and_misses_expected_fail():
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "FAIL", "R5": "PASS"}
    bundle = fixture_bundle(expected)
    bundle["findings"][3]["result"] = "INCONCLUSIVE"
    bundle["findings"][3]["inconclusive_reason"] = "NODE_UNAVAILABLE"
    result = evaluate_bundle(bundle)
    assert result["status"] == "COMPLETE" and result["matches_label"] is False
    assert result["rules"][3]["actual"] == "INCONCLUSIVE"
    assert result["metrics"]["fail_recall"] == 0
    assert result["partial_counts"]["inconclusive"] == 1


def test_expected_nonzero_counter_is_judged_separately():
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "FAIL", "R5": "PASS"}
    bundle = fixture_bundle(expected)
    bundle["findings"][3]["observed"]["roster_chain_breaks"] = 0
    result = evaluate_bundle(bundle)
    assert result["status"] == "COMPLETE" and result["matches_label"] is False
    assert result["metrics"]["exact_rule_result_accuracy"] == 1
    assert result["rules"][3]["missing_expected_nonzero"] == ["roster_chain_breaks"]


def test_nonzero_set_is_exact_including_negative_and_boolean_numbers():
    bundle = fixture_bundle()
    bundle["findings"][0]["observed"].update({"unknown_tokens": -1, "unknown_nullifiers": True})
    result = evaluate_bundle(bundle)
    assert result["status"] == "COMPLETE" and result["matches_label"] is False
    assert result["rules"][0]["unexpected_nonzero"] == ["unknown_nullifiers", "unknown_tokens"]


def test_private_unknown_numeric_fields_are_counted_without_exporting_values():
    finding, record = raw_finding(1, observed={"private_unknown_field": 123456, "unknown_tokens": 0})
    reduced, invalid = reduce_findings([finding], [record], election_id=ELECTION,
        checkpoint=2, checkpoint_event_id=CP_EVENT, observed_keys=set())
    assert invalid == 0 and reduced[0]["omitted_numeric_nonzero_count"] == 1
    assert "private_unknown_field" not in json.dumps(reduced) and "123456" not in json.dumps(reduced)
    bundle = fixture_bundle()
    bundle["findings"][0] = reduced[0]
    assert evaluate_bundle(bundle)["matches_label"] is False


def test_approved_mapping_is_frozen_and_t05_primary_cause_mismatch_is_preserved(tmp_path):
    path, commit, _manifest = mapping_repository(tmp_path)
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    assert mapping is not None and provenance["available"] is True
    assert provenance["approval_independently_verified"] is False
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "FAIL", "R5": "FAIL"}
    bundle = with_mapping(fixture_bundle(expected), mapping, provenance,
                          observations={"R4": {"roster_chain_breaks": 1}, "R5": {"root_mismatches": 1}})
    before_label = deepcopy(bundle["provenance"]["label"])
    result = evaluate_bundle(bundle)
    assert result["root_cause_status"] == "MEASURED" and result["root_cause_accuracy"] == 0
    assert result["primary_cause"]["predicted"] == "UNAUTHORIZED_ADMIN_ACTION"
    assert result["primary_cause"]["expected"] == "DATA_TAMPERING"
    assert result["primary_cause"]["rule"] == "R4"
    assert bundle["provenance"]["label"] == before_label
    assert result["official_scenario_verified"] is False
    report = evaluate_many([bundle])
    group = report["groups"][0]["cause_groups"][mapping.fingerprint]
    assert group["fault_label_runs"] == 1 and group["correct_fault_causes"] == 0
    assert group["root_cause_accuracy"] == 0
    assert group["root_cause_per_seed_min_median_max"]["n"] == 1


@pytest.mark.parametrize("committed_newline,checkout_newline", [(b"\n", b"\r\n"), (b"\r\n", b"\n")])
def test_frozen_mapping_accepts_only_git_checkout_line_ending_conversion(tmp_path, committed_newline, checkout_newline):
    path, commit, _manifest = mapping_repository(tmp_path, encoding_newline=committed_newline)
    encoded = subprocess.check_output(["git", "-C", str(tmp_path), "show", f"{commit}:rules/config/unit-test-map.json"])
    assert encoded == path.read_bytes()
    checkout = encoded.replace(b"\r\n", b"\n").replace(b"\n", checkout_newline)
    assert checkout != encoded
    path.write_bytes(checkout)
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    assert mapping is not None and provenance["available"] is True
    # Evidence hashes and bytes bind the original Git object, not its checkout.
    assert provenance["encoding_content_utf8"].encode("utf-8") == encoded
    assert provenance["encoding_content_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert provenance["encoding_content_sha256"] != hashlib.sha256(checkout).hexdigest()
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "PASS", "R5": "FAIL"}
    bundle = with_mapping(fixture_bundle(expected), mapping, provenance, observations={"R5": {"root_mismatches": 1}})
    assert evaluate_bundle(bundle)["root_cause_status"] == "MEASURED"


@pytest.mark.parametrize("mutation", ["content", "indent", "bare_cr", "escaped_newline"])
def test_checkout_line_ending_allowance_does_not_accept_other_edits(tmp_path, mutation):
    path, commit, _manifest = mapping_repository(tmp_path, encoding_newline=b"\n")
    encoded = path.read_bytes()
    if mutation == "content":
        changed = encoded.replace(b'"DATA_TAMPERING"', b'"PROCESSING_BUG"', 1)
    elif mutation == "indent":
        changed = encoded.replace(b'\n  "', b'\n    "', 1)
    elif mutation == "bare_cr":
        changed = encoded.replace(b"\n", b"\r", 1)
    else:
        # A JSON string escape is content, not a physical checkout line ending.
        changed = encoded.replace(b'"explanation": "', b'"explanation": "\\n', 1)
    assert changed != encoded
    path.write_bytes(changed.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    assert mapping is None and provenance["reason"] == "MAPPING_ENCODING_DIFFERS_FROM_PINNED_COMMIT"


@pytest.mark.parametrize("mutation,reason", [
    ("proposed", "MAPPING_NOT_APPROVED"),
    ("stale", "MAPPING_INVALID_OR_APPROVAL_STALE"),
    ("source_after_run", "MAPPING_SOURCE_COMMITTED_AFTER_RUN_START"),
    ("encoding_after_run", "MAPPING_ENCODING_COMMITTED_AFTER_RUN_START"),
    ("edited_encoding", "MAPPING_ENCODING_DIFFERS_FROM_PINNED_COMMIT"),
    ("no_encoding_pin", "MAPPING_ENCODING_NOT_PINNED"),
])
def test_unaccepted_stale_postrun_or_mutable_mapping_never_produces_cause_metric(tmp_path, mutation, reason):
    path, commit, manifest = mapping_repository(tmp_path,
        source_time="2026-11-25T00:00:00Z" if mutation == "source_after_run" else "2020-01-01T00:00:00Z",
        encoding_time="2026-11-25T00:10:00Z" if mutation in {"source_after_run", "encoding_after_run"} else "2020-01-02T00:00:00Z",
        status="proposed" if mutation == "proposed" else "approved")
    if mutation == "stale":
        manifest["approval"]["source_commit"] = "b" * 40
        path.write_text(json.dumps(manifest), encoding="utf-8")
    elif mutation == "edited_encoding":
        manifest["rows"][5]["cause_code"] = "DATA_TAMPERING"
        path.write_text(json.dumps(manifest), encoding="utf-8")
    mapping, provenance = frozen_mapping(path, tmp_path, START, None if mutation == "no_encoding_pin" else commit)
    assert mapping is None and provenance["available"] is False and provenance["reason"] == reason
    bundle = with_mapping(fixture_bundle(), mapping, provenance)
    result = evaluate_bundle(bundle)
    assert result["root_cause_accuracy"] is None
    assert result["root_cause_status"] == "NOT_EVALUATED_NO_FROZEN_ACCEPTED_MAPPING"
    assert result["metrics"] is not None  # Mapping refusal does not erase valid rule measurements.


@pytest.mark.parametrize("mutation", ["manifest", "encoding", "encoding_time", "row"])
def test_offline_cause_evaluation_rechecks_mapping_and_prediction_provenance(tmp_path, mutation):
    path, commit, _manifest = mapping_repository(tmp_path)
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "FAIL", "R5": "PASS"}
    bundle = with_mapping(fixture_bundle(expected), mapping, provenance)
    if mutation == "manifest":
        bundle["provenance"]["b1_mapping"]["manifest"]["rows"][5]["cause_code"] = "DATA_TAMPERING"
    elif mutation == "encoding":
        bundle["provenance"]["b1_mapping"]["encoding_content_sha256"] = "0" * 64
    elif mutation == "encoding_time":
        bundle["provenance"]["b1_mapping"]["encoding_commit_time"] = "2026-11-25T00:00:00Z"
    else:
        bundle["findings"][3]["predicted_cause"]["row_index"] = 7
    result = evaluate_bundle(bundle)
    assert result["root_cause_accuracy"] is None
    assert result["root_cause_status"].startswith("NOT_EVALUATED_")


def test_r3_cause_is_selected_before_private_arrays_are_reduced(tmp_path):
    path, commit, _manifest = mapping_repository(tmp_path)
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    expected = {"R1": "PASS", "R2": "PASS", "R3": "FAIL", "R4": "PASS", "R5": "PASS"}
    bundle = with_mapping(fixture_bundle(expected), mapping, provenance,
                          observations={"R3": {"count_relationship_violations": ["tokens_exceed_roster"]}})
    assert "count_relationship_violations" not in bundle["findings"][2]["observed"]
    assert bundle["findings"][2]["predicted_cause"]["cause_code"] == "PROCESSING_BUG"
    assert evaluate_bundle(bundle)["primary_cause"]["predicted"] == "PROCESSING_BUG"


@pytest.mark.parametrize("counter,accuracy", [(1, 1), (0, 0)])
def test_accepted_mapping_measures_correct_and_unmatched_fault_causes(tmp_path, counter, accuracy):
    path, commit, _manifest = mapping_repository(tmp_path)
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "PASS", "R5": "FAIL"}
    bundle = with_mapping(fixture_bundle(expected), mapping, provenance,
                          observations={"R5": {"root_mismatches": counter}})
    result = evaluate_bundle(bundle)
    assert result["root_cause_status"] == "MEASURED"
    assert result["root_cause_accuracy"] == accuracy
    assert result["primary_cause"]["predicted"] == ("DATA_TAMPERING" if counter else None)
    group = evaluate_many([bundle])["groups"][0]["cause_groups"][mapping.fingerprint]
    assert group["fault_label_runs"] == 1
    assert group["no_cause_fault_runs"] == 1 - counter


def test_null_cause_label_is_reported_separately_from_fault_accuracy(tmp_path):
    path, commit, _manifest = mapping_repository(tmp_path)
    mapping, provenance = frozen_mapping(path, tmp_path, START, commit)
    bundle = with_mapping(fixture_bundle(), mapping, provenance)
    # Only this synthetic in-memory label changes; no project label is touched.
    label = bundle["provenance"]["label"]
    label["body"]["cause_code"] = None
    label["content_utf8"] = json.dumps(label["body"], sort_keys=True)
    label["sha256"] = hashlib.sha256(label["content_utf8"].encode()).hexdigest()
    result = evaluate_bundle(bundle)
    assert result["root_cause_status"] == "NO_FAULT_CAUSE_LABEL" and result["root_cause_accuracy"] is None
    assert result["primary_cause"]["matches_label"] is True
    group = evaluate_many([bundle])["groups"][0]["cause_groups"][mapping.fingerprint]
    assert group["fault_label_runs"] == 0 and group["root_cause_accuracy"] is None
    assert group["cause_label_runs"] == 1 and group["primary_cause_agreement"] == 1


def test_a_later_pass_never_supersedes_fail_for_measurement():
    expected = {"R1": "PASS", "R2": "PASS", "R3": "PASS", "R4": "FAIL", "R5": "PASS"}
    bundle = fixture_bundle(expected)
    later = deepcopy(bundle["findings"][3])
    later.update({"finding_id": "fnd_" + "8" * 26, "checked_at": "2026-11-24T00:11:00Z", "result": "PASS"})
    bundle["findings"].append(later)
    result = evaluate_bundle(bundle)
    assert result["rules"][3]["actual"] == "FAIL"
    assert result["rules"][3]["selection"] == "FIRST_FAIL_PRESERVED"


def test_unresolved_pass_inconclusive_mix_is_ambiguous():
    bundle = fixture_bundle()
    extra = deepcopy(bundle["findings"][0])
    extra.update({"finding_id": "fnd_" + "8" * 26, "result": "INCONCLUSIVE", "contract_status_from_gateway": "PENDING"})
    bundle["findings"].append(extra)
    result = evaluate_bundle(bundle)
    assert result["status"] == "INCOMPLETE"
    assert result["rules"][0]["selection"] == "AMBIGUOUS_NONFAIL_RESULTS"
    extra["contract_status_from_gateway"] = "SUPERSEDED"
    assert evaluate_bundle(bundle)["rules"][0]["actual"] == "PASS"


def test_unverified_candidate_cannot_be_silently_dropped_to_improve_result():
    bundle = fixture_bundle()
    extra = deepcopy(bundle["findings"][0])
    extra.update({"finding_id": "fnd_" + "8" * 26, "result": "FAIL"})
    extra["binding"].update({"matched": False, "status": "RECORD_MISMATCH"})
    bundle["findings"].append(extra)
    result = evaluate_bundle(bundle)
    assert result["status"] == "INCOMPLETE" and result["rules"][0]["actual"] is None


@pytest.mark.parametrize("mutation", ["hash", "after_run", "scenario"])
def test_changed_or_posthoc_labels_are_not_confirmatory(mutation):
    bundle = fixture_bundle()
    label = bundle["provenance"]["label"]
    if mutation == "hash":
        label["sha256"] = "0" * 64
    elif mutation == "after_run":
        label["commit_time"] = "2026-11-25T00:00:00Z"
    else:
        label["body"]["scenario"] = "T08a"
    result = evaluate_bundle(bundle)
    assert result["status"] == "INCOMPLETE" and result["metrics"] is None


def test_repeated_exports_cannot_count_as_independent_runs():
    first = fixture_bundle()
    second = deepcopy(first)
    second["run"]["run_id"] = "another-export"
    with pytest.raises(ValueError, match="Duplicate"):
        evaluate_many([first, second])


def test_pooled_seeds_cannot_silently_change_the_scenario_label():
    first = fixture_bundle()
    second = fixture_bundle(run_id="fixture-seed2")
    second["run"]["seed"] = 2
    label = second["provenance"]["label"]
    label["body"]["cause_code"] = "PROCESSING_BUG"
    label["content_utf8"] = json.dumps(label["body"], sort_keys=True)
    label["sha256"] = hashlib.sha256(label["content_utf8"].encode()).hexdigest()
    assert evaluate_bundle(second)["status"] == "COMPLETE"
    with pytest.raises(ValueError, match="Incompatible label revisions"):
        evaluate_many([first, second])


def test_label_source_must_predate_first_scenario_attempt_even_when_incomplete():
    first = fixture_bundle()
    first["findings"].pop()
    second = fixture_bundle(run_id="fixture-seed2")
    second["run"].update({"seed": 2, "started_at": "2026-11-24T00:06:00Z"})
    second["provenance"]["label"].update({"commit": "b" * 40, "commit_time": "2026-11-24T00:05:00Z"})
    assert evaluate_bundle(second)["status"] == "COMPLETE"
    with pytest.raises(ValueError, match="first run"):
        evaluate_many([first, second])


def test_mock_and_declared_real_runs_are_never_pooled():
    first = fixture_bundle()
    second = fixture_bundle(source="real-declared", run_id="fixture-2")
    second["run"]["seed"] = 2
    report = evaluate_many([first, second])
    assert len(report["groups"]) == 2
    assert all(group["complete_runs"] == 1 for group in report["groups"])
    assert report["official_scenario_verification"] is False


def test_incomplete_runs_visible_but_excluded_from_pooled_metrics():
    first = fixture_bundle()
    second = fixture_bundle(run_id="fixture-2")
    second["run"]["seed"] = 2
    second["findings"].pop()
    group = evaluate_many([first, second])["groups"][0]
    assert group["total_runs"] == 2 and group["complete_runs"] == 1 and group["incomplete_runs"] == 1
    assert group["scenario_seed_coverage"]["T05-db-add"]["missing_minimum_seeds"] == [2, 3]
    assert group["missing_mandatory_families"] == ["T01", "T02", "T04", "T08", "T15"]
    assert group["per_seed_min_median_max"]["exact_rule_result_accuracy"]["n"] == 1


def test_csv_and_markdown_identifiers_cannot_contain_formulas_or_markup():
    bundle = fixture_bundle()
    bundle["run"]["run_id"] = '=HYPERLINK("https://example.com")'
    with pytest.raises(ValueError, match="identifiers"):
        evaluate_bundle(bundle)


def test_committed_label_ignores_working_tree_edits(tmp_path):
    # This is an isolated unit-test repository, never the project's scenario files.
    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True,
                              env=os.environ | {"GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00Z"}).stdout
    git("init", "-q")
    git("config", "user.name", "Unit test")
    git("config", "user.email", "unit@example.invalid")
    path = tmp_path / "tests/scenarios/T05-db-add/expected.json"
    path.parent.mkdir(parents=True)
    original = label_metadata()["body"]
    path.write_text(json.dumps(original), encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "Synthetic unit-test label")
    commit = git("rev-parse", "HEAD").decode().strip()
    path.write_text('{"scenario":"edited after the run"}', encoding="utf-8")
    frozen = committed_label(tmp_path, "T05-db-add", commit, START)
    assert frozen["body"] == original and frozen["precommitted"] is True
    assert committed_label(tmp_path, "T15a", commit, START)["available"] is False


@pytest.mark.parametrize("url", ["https://user:secret@example.com", "https://example.com?key=secret", "file:///tmp/x", "http://example.com/api"])
def test_origins_reject_embedded_credentials_and_non_http(url):
    with pytest.raises(ValueError):
        safe_base_url(url)


def test_collector_is_get_only_and_keeps_missing_gateway_reads_incomplete():
    calls = []
    pairs = [raw_finding(i) for i in range(1, 6)]
    def handler(request):
        calls.append(request)
        assert request.method == "GET" and request.headers["X-Service-Key"] == "test-agent-key"
        if request.url.path == "/internal/v1/elections":
            body = {"items": [{"election_id": ELECTION, "status": "TALLIED"}]}
        elif request.url.path == "/internal/v1/checkpoints":
            body = {"items": [{"checkpoint": 2, "event_id": CP_EVENT, "ledger_status": "ACCEPTED", "reason": "TALLY"}]}
        elif request.url.path == "/internal/v1/findings":
            body = {"items": [p[0] for p in pairs], "next_cursor": None}
        elif request.url.path == "/v1/finding-records":
            body = {"items": [p[1] for p in pairs], "next_cursor": None}
        elif request.url.path == "/v1/chain":
            body = {"platform": "other", "chain_id": "42", "rpc_urls": ["http://user:rpc-secret@node/"]}
        else:
            return httpx.Response(503, json={"secret": "NEVER-LOG"})
        return httpx.Response(200, json=body)
    services = ReadOnlyServices("http://core", "http://gateway", "test-agent-key", transport=httpx.MockTransport(handler))
    try:
        bundle = collect_bundle(services, election_id=ELECTION, checkpoint=2, run_id="fixture-collector", scenario="T05-db-add",
            seed=1, configuration="demo", started_at=START, source_mode="mock", deployment_commit=COMMIT,
            label=label_metadata(), collector_commit=COMMIT, collected_at=CAPTURE)
    finally:
        services.close()
    assert len(calls) == 6 and bundle["collection"]["complete"] is False
    text = json.dumps(bundle)
    assert all(secret not in text for secret in ("test-agent-key", "rpc-secret", "NEVER-LOG", "DO-NOT-SAVE-THIS", "evr_"))
    assert evaluate_bundle(bundle)["metrics"] is None


def test_redirect_is_not_followed_and_repeated_cursor_stops():
    calls = []
    def redirect(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://unrelated.example/collect-key"})
    service = ReadOnlyServices("http://core", "http://gateway", "secret", transport=httpx.MockTransport(redirect))
    try:
        with pytest.raises(ReadError):
            service.get("core", "/internal/v1/findings")
        assert len(calls) == 1
    finally:
        service.close()
    def loop(request):
        return httpx.Response(200, json={"items": [], "next_cursor": "repeated"})
    service = ReadOnlyServices("http://core", "http://gateway", "secret", transport=httpx.MockTransport(loop))
    try:
        with pytest.raises(ReadError, match="cursor"):
            service.pages("core", "/internal/v1/findings", {})
    finally:
        service.close()
