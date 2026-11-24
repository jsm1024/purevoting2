"""Evaluate collected rule decisions against immutable pre-run scenario labels.

Missing, invalid or ambiguous measurements are NOT_EVALUATED. Mock/development
runs are kept in different groups from operator-declared real runs. This script
does not claim T01/E1 completion, independently verified chain evidence, or B2 AI
results from a template audit report.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from collect_rule_evidence import ELECTION, FORMAT, RUN_ID, SCENARIO, SHA, SOURCE_MODES, parse_time, write_new_json
from purevoting_rules.findings import contract_validator
from purevoting_rules.hashing import canonical

RULES = ("R1", "R2", "R3", "R4", "R5")
RESULTS = {"PASS", "FAIL", "INCONCLUSIVE"}
ID = re.compile(r"^fnd_[0-9A-HJKMNP-TV-Z]{26}$")
COUNTER = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
CAUSE_VALIDATOR = contract_validator({"$ref": "common.schema.json#/$defs/CauseCode"}, filename="evaluation-cause-wrapper.schema.json")


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _label(bundle: dict) -> tuple[dict | None, list[str]]:
    label = bundle.get("provenance", {}).get("label", {})
    if label.get("available") is not True:
        return None, ["COMMITTED_LABEL_UNAVAILABLE"]
    try:
        raw = label["content_utf8"].encode("utf-8")
        body = json.loads(raw)
        if hashlib.sha256(raw).hexdigest() != label["sha256"] or body != label["body"]:
            raise ValueError("Label hash mismatch")
        if body["scenario"] != bundle["run"]["scenario"] or not SHA.fullmatch(label["commit"]):
            raise ValueError("Label source mismatch")
        if label["path"] != f"tests/scenarios/{body['scenario']}/expected.json":
            raise ValueError("Label path mismatch")
        if set(body["rules"]) != set(RULES) or any(x not in RESULTS for x in body["rules"].values()):
            raise ValueError("Invalid expected rules")
        nonzero = body.get("observed_nonzero", {})
        if not isinstance(nonzero, dict) or not set(nonzero) <= set(RULES):
            raise ValueError("Invalid expected observations")
        for keys in nonzero.values():
            if not isinstance(keys, list) or any(not isinstance(k, str) or not COUNTER.fullmatch(k) for k in keys):
                raise ValueError("Invalid expected observation key")
        if parse_time(label["commit_time"]) > parse_time(bundle["run"]["started_at"]):
            return body, ["LABEL_COMMITTED_AFTER_RUN_START"]
    except (ValueError, TypeError, KeyError, AttributeError):
        return None, ["COMMITTED_LABEL_INVALID"]
    return body, []


def _selection(candidates: list[dict]) -> tuple[dict | None, str]:
    if not candidates:
        return None, "MISSING"
    by_id = {}
    for candidate in candidates:
        key = candidate["finding_id"]
        if key in by_id and by_id[key] != candidate:
            return None, "CONFLICTING_FINDING_ID"
        by_id[key] = candidate
    ordered = sorted(by_id.values(), key=lambda x: (parse_time(x["checked_at"]), x["finding_id"]))
    # A FAIL is never made harmless by a later PASS. Preserve the first FAIL.
    failures = [row for row in ordered if row["result"] == "FAIL"]
    if failures:
        return failures[0], "FIRST_FAIL_PRESERVED"
    if len({row["result"] for row in ordered}) == 1:
        return ordered[-1], "LATEST_SAME_RESULT"
    passes = [row for row in ordered if row["result"] == "PASS"]
    unknown = [row for row in ordered if row["result"] == "INCONCLUSIVE"]
    if passes and all(row.get("contract_status_from_gateway") == "SUPERSEDED" for row in unknown):
        # This remains the Gateway's reported status, explicitly not a node proof.
        return passes[-1], "GATEWAY_REPORTED_SUPERSESSION"
    return None, "AMBIGUOUS_NONFAIL_RESULTS"


def _metrics(counts: dict) -> dict:
    return {
        "fail_precision": _ratio(counts["tp"], counts["tp"] + counts["fp"]),
        "fail_recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
        "fail_false_positive_rate": _ratio(counts["fp"], counts["fp"] + counts["tn"]),
        "exact_rule_result_accuracy": _ratio(counts["exact_matches"], counts["rules"]),
        "inconclusive_fraction": _ratio(counts["inconclusive"], counts["rules"]),
    }


def _causes(bundle: dict, selected: list[dict], label: dict | None, complete: bool) -> dict:
    """Judge the frozen first-match table without rewriting a disagreeing label.

    The collector computes each match from the full immutable body in memory.
    Its export intentionally omits raw evidence arrays; the evaluator checks the
    saved manifest fingerprint and row provenance, not a cryptographic proof of
    that in-memory calculation or of the operator's approval claim.
    """
    metadata = bundle.get("provenance", {}).get("b1_mapping") or {}
    result = {"status": "NOT_EVALUATED_NO_FROZEN_ACCEPTED_MAPPING", "accuracy": None,
              "expected": (label or {}).get("cause_code"), "predicted": None,
              "matches_label": None, "rule": None, "row_index": None,
              "mapping_sha256": None,
              "policy": "First matching table row across the selected R1-R5 findings; minimum row index",
              "metric_definition": "Correct primary causes divided by runs with a non-null injected-fault cause label",
              "approval_is_operator_supplied": True, "approval_independently_verified": False}
    if not isinstance(metadata, dict) or metadata.get("available") is not True:
        result["mapping_unavailable_reason"] = metadata.get("reason", "MAPPING_NOT_SUPPLIED") if isinstance(metadata, dict) else "MAPPING_METADATA_INVALID"
        return result
    try:
        manifest = metadata["manifest"]
        if (metadata["status"] != "approved" or manifest["status"] != "approved" or
                manifest["schema_version"] != "1" or not HASH.fullmatch(metadata["sha256"]) or
                hashlib.sha256(canonical(manifest)).hexdigest() != metadata["sha256"]):
            raise ValueError("Unaccepted or changed mapping manifest")
        source = manifest["source"]
        approval = manifest["approval"]
        if (not SHA.fullmatch(source["commit"]) or metadata["source_commit"] != source["commit"] or
                approval["source_commit"] != source["commit"] or
                not isinstance(approval["reference"], str) or not approval["reference"] or
                metadata["review_reference"] != approval["reference"] or
                metadata["source_path"] != source["path"] or
                not HASH.fullmatch(metadata["source_content_sha256"])):
            raise ValueError("Stale or unavailable mapping source")
        if parse_time(metadata["source_commit_time"]) > parse_time(bundle["run"]["started_at"]):
            result["status"] = "NOT_EVALUATED_MAPPING_SOURCE_POSTDATES_RUN"
            return result
        encoded = metadata["encoding_content_utf8"].encode("utf-8")
        encoding_path = metadata["encoding_path"]
        if (not SHA.fullmatch(metadata["encoding_commit"]) or
                not isinstance(encoding_path, str) or not encoding_path or encoding_path.startswith(("/", "\\")) or
                ".." in encoding_path.split("/") or "\\" in encoding_path or
                hashlib.sha256(encoded).hexdigest() != metadata["encoding_content_sha256"] or json.loads(encoded) != manifest):
            raise ValueError("Unpinned or changed mapping encoding")
        if parse_time(metadata["encoding_commit_time"]) > parse_time(bundle["run"]["started_at"]):
            result["status"] = "NOT_EVALUATED_MAPPING_ENCODING_POSTDATES_RUN"
            return result
        mapping_rows = manifest["rows"]
        if not isinstance(mapping_rows, list) or not 1 <= len(mapping_rows) <= 100:
            raise ValueError("Invalid mapping rows")
        matches = []
        for finding in selected:
            if "predicted_cause" not in finding:
                raise ValueError("Missing cause measurement")
            prediction = finding["predicted_cause"]
            if prediction is None:
                continue
            row_index = prediction["row_index"]
            if (finding["result"] == "PASS" or type(row_index) is not int or not 0 <= row_index < len(mapping_rows) or
                    prediction["mapping_sha256"] != metadata["sha256"] or not CAUSE_VALIDATOR.is_valid(prediction["cause_code"])):
                raise ValueError("Invalid cause measurement")
            row = mapping_rows[row_index]
            if (row["cause_code"] != prediction["cause_code"] or row["rule_id"] not in {finding["rule_id"], "*"} or
                    row["result"] != finding["result"]):
                raise ValueError("Cause does not match frozen table row")
            matches.append((row_index, RULES.index(finding["rule_id"]), finding["finding_id"], prediction["cause_code"]))
    except (ValueError, TypeError, KeyError, AttributeError):
        result["status"] = "NOT_EVALUATED_INVALID_MAPPING_OR_PREDICTION"
        return result
    result["mapping_sha256"] = metadata["sha256"]
    if not complete:
        result["status"] = "NOT_EVALUATED_INCOMPLETE_RULE_MEASUREMENT"
        return result
    if label is None or "cause_code" not in label or (label["cause_code"] is not None and not CAUSE_VALIDATOR.is_valid(label["cause_code"])):
        result["status"] = "NOT_EVALUATED_CAUSE_LABEL_UNAVAILABLE"
        return result
    if matches:
        index, rule_index, _finding_id, cause = min(matches)
        result.update({"row_index": index, "rule": RULES[rule_index], "predicted": cause})
    result["matches_label"] = result["predicted"] == label["cause_code"]
    if label["cause_code"] is None:
        result["status"] = "NO_FAULT_CAUSE_LABEL"
    else:
        result.update({"status": "MEASURED", "accuracy": int(result["matches_label"])})
    return result


def evaluate_bundle(bundle: dict) -> dict:
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        raise ValueError("Unsupported evidence bundle format")
    run = bundle["run"]
    if (not RUN_ID.fullmatch(run.get("run_id", "")) or not SCENARIO.fullmatch(run.get("scenario", "")) or
            not ELECTION.fullmatch(run.get("election_id", "")) or type(run.get("seed")) is not int or run["seed"] < 0):
        raise ValueError("Invalid run identifiers or seed")
    if run.get("source_mode") not in SOURCE_MODES or run.get("configuration") not in {"demo", "evaluation"}:
        raise ValueError("Unknown run source or configuration")
    if not SHA.fullmatch(run.get("declared_deployment_commit", "")):
        raise ValueError("Deployment revision is required")
    started, captured = parse_time(run["started_at"]), parse_time(bundle["collected_at"])
    if started > captured or type(run["judged_checkpoint"]) is not int or run["judged_checkpoint"] < 0:
        raise ValueError("Invalid run interval or checkpoint")
    label, errors = _label(bundle)
    if bundle.get("collection", {}).get("complete") is not True:
        errors.append("COLLECTION_INCOMPLETE")
    checkpoint = bundle.get("checkpoint") or {}
    if checkpoint.get("checkpoint") != run["judged_checkpoint"] or checkpoint.get("ledger_status") != "ACCEPTED":
        errors.append("JUDGED_CHECKPOINT_NOT_ACCEPTED")
    election = bundle.get("election") or {}
    if election.get("election_id") != run["election_id"]:
        errors.append("ELECTION_MISMATCH_OR_MISSING")
    by_rule = {rule: [] for rule in RULES}
    invalid_rules = set()
    for row in bundle.get("findings", []):
        try:
            rule = row["rule_id"]
            if rule not in RULES or not ID.fullmatch(row["finding_id"]):
                raise ValueError("Invalid decision identifier")
            if (row["election_id"] != run["election_id"] or row["checkpoint"] != run["judged_checkpoint"] or
                    not started <= parse_time(row["checked_at"]) <= captured or row["result"] not in RESULTS or
                    not re.fullmatch(r"[0-9a-f]{64}", row["body_sha256"])):
                raise ValueError("Decision does not belong to the judged run")
            if row["binding"].get("matched") is not True or row["binding"].get("status") != "MATCHED":
                invalid_rules.add(rule)
                continue
            if not isinstance(row["observed"], dict) or any(v is not None and type(v) not in (bool, int) for v in row["observed"].values()):
                raise ValueError("Only reduced numeric observations may be evaluated")
            omitted = row.get("omitted_numeric_nonzero_count", 0)
            if type(omitted) is not int or omitted < 0:
                raise ValueError("Invalid reduced nonzero count")
            by_rule[rule].append(row)
        except (KeyError, TypeError, ValueError, AttributeError):
            errors.append("INVALID_REDUCED_DECISION")
            if isinstance(row, dict) and row.get("rule_id") in RULES:
                invalid_rules.add(row["rule_id"])
    counts = dict.fromkeys(("tp", "fp", "tn", "fn", "rules", "exact_matches", "inconclusive"), 0)
    rows, selected_findings = [], []
    complete = label is not None and not errors
    for rule in RULES:
        selected, selection = _selection(by_rule[rule])
        if rule in invalid_rules:
            selected, selection = None, "UNVERIFIED_OR_INVALID_CANDIDATE"
        expected = label["rules"][rule] if label else None
        actual = selected["result"] if selected else None
        required = (label or {}).get("observed_nonzero", {}).get(rule, [])
        nonzero = {key for key, value in selected["observed"].items() if value} if selected else set()
        missing = sorted(set(required) - nonzero)
        unexpected = sorted(nonzero - set(required))
        omitted = selected.get("omitted_numeric_nonzero_count", 0) if selected else 0
        row = {"rule": rule, "expected": expected, "actual": actual,
               "measurement_status": "MEASURED" if selected else "NOT_EVALUATED",
               "selection": selection, "finding_id": selected["finding_id"] if selected else None,
               "result_matches": actual == expected if selected and label else None,
               "missing_expected_nonzero": missing, "unexpected_nonzero": unexpected,
               "omitted_numeric_nonzero_count": omitted,
               "observations_match": not (missing or unexpected or omitted) if selected and label else None}
        rows.append(row)
        if selected is None or label is None:
            complete = False
            continue
        selected_findings.append(selected)
        counts["rules"] += 1
        counts["exact_matches"] += int(actual == expected)
        counts["inconclusive"] += int(actual == "INCONCLUSIVE")
        if expected in {"PASS", "FAIL"}:
            # Binary FAIL detection is separate from exact PASS/FAIL/INCONCLUSIVE.
            # INCONCLUSIVE is not a detected FAIL and is never relabelled PASS.
            counts["tp" if expected == "FAIL" and actual == "FAIL" else
                   "fn" if expected == "FAIL" else
                   "fp" if actual == "FAIL" else "tn"] += 1
    matches = complete and all(row["result_matches"] and row["observations_match"] for row in rows)
    causes = _causes(bundle, selected_findings, label, complete)
    mapping = bundle.get("provenance", {}).get("b1_mapping") or {}
    if not isinstance(mapping, dict):
        mapping = {}
    return {
        "run": run, "status": "COMPLETE" if complete else "INCOMPLETE",
        "matches_label": matches if complete else None,
        "label_match_scope": "Rule results and exact nonzero numeric observations; cause and refusal outcomes are separate",
        "errors": sorted(set(errors)), "rules": rows, "partial_counts": counts,
        "metrics": _metrics(counts) if complete else None,
        "label_source": {k: bundle.get("provenance", {}).get("label", {}).get(k) for k in ("path", "commit", "sha256", "commit_time")},
        "root_cause_accuracy": causes["accuracy"], "root_cause_status": causes["status"],
        "primary_cause": causes,
        "mapping_source": {key: mapping.get(key) for key in ("version", "status", "sha256", "source_commit", "source_commit_time",
                              "source_path", "source_content_sha256", "review_reference", "approval_is_operator_supplied",
                              "approval_independently_verified", "encoding_commit", "encoding_path", "encoding_commit_time",
                              "encoding_content_sha256")},
        "evidence_validity_rate": None,
        "evidence_validity_status": "Use the separate read-only audit report evidence validator",
        "official_scenario_verified": False,
        "end_to_end": bundle.get("end_to_end", {}),
    }


def evaluate_many(bundles: list[dict]) -> dict:
    runs, ids, identities = [], set(), set()
    for bundle in bundles:
        run = bundle["run"]
        identity = tuple(run.get(k) for k in ("declared_deployment_commit", "scenario", "seed", "election_id", "judged_checkpoint"))
        if run["run_id"] in ids or identity in identities:
            raise ValueError("Duplicate run identity; repeated exports are not independent runs")
        ids.add(run["run_id"])
        identities.add(identity)
        runs.append(evaluate_bundle(bundle))
    # Labels are fixed before the first run of a scenario, not revised between
    # seeds. Include incomplete attempts when locating that first start time.
    label_cohorts = {}
    for item in runs:
        run = item["run"]
        key = (run["source_mode"], run["configuration"], run["declared_deployment_commit"], run["scenario"])
        cohort = label_cohorts.setdefault(key, {"first_start": parse_time(run["started_at"]), "labels": []})
        cohort["first_start"] = min(cohort["first_start"], parse_time(run["started_at"]))
        if item["status"] == "COMPLETE":
            cohort["labels"].append(item["label_source"])
    for cohort in label_cohorts.values():
        if len({label["sha256"] for label in cohort["labels"]}) > 1:
            raise ValueError("Incompatible label revisions in one scenario group; labels cannot change between seeds")
        if any(parse_time(label["commit_time"]) > cohort["first_start"] for label in cohort["labels"]):
            raise ValueError("Label source was committed after the first run in its scenario group")
    groups = {}
    for item in runs:
        run = item["run"]
        key = (run["source_mode"], run["configuration"], run["declared_deployment_commit"])
        group = groups.setdefault(key, {"source_mode": key[0], "configuration": key[1], "deployment_commit": key[2],
                                      "total_runs": 0, "complete_runs": 0, "incomplete_runs": 0,
                                      "label_matching_runs": 0, "counts": dict.fromkeys(item["partial_counts"], 0),
                                      "values": {}, "seed_counts": {}, "scenario_seeds": {},
                                      "cause_unmeasured_runs": 0, "cause_groups": {}})
        group["total_runs"] += 1
        group["scenario_seeds"].setdefault(run["scenario"], set())
        if item["root_cause_status"] not in {"MEASURED", "NO_FAULT_CAUSE_LABEL"}:
            group["cause_unmeasured_runs"] += 1
        if item["status"] != "COMPLETE":
            group["incomplete_runs"] += 1
            continue
        group["complete_runs"] += 1
        group["scenario_seeds"][run["scenario"]].add(run["seed"])
        seed_counts = group["seed_counts"].setdefault(run["seed"], dict.fromkeys(item["partial_counts"], 0))
        group["label_matching_runs"] += int(item["matches_label"])
        for name, value in item["partial_counts"].items():
            group["counts"][name] += value
            seed_counts[name] += value
        for name, value in item["metrics"].items():
            if value is not None:
                group["values"].setdefault(name, []).append(value)
        cause = item["primary_cause"]
        if cause["status"] in {"MEASURED", "NO_FAULT_CAUSE_LABEL"}:
            cause_group = group["cause_groups"].setdefault(cause["mapping_sha256"], {
                "mapping_source": item["mapping_source"], "fault_label_runs": 0, "correct_fault_causes": 0,
                "cause_label_runs": 0, "primary_cause_agreements": 0, "no_cause_fault_runs": 0, "seeds": {},
            })
            seed = cause_group["seeds"].setdefault(run["seed"], {"fault_label_runs": 0, "correct_fault_causes": 0,
                                                               "cause_label_runs": 0, "primary_cause_agreements": 0,
                                                               "no_cause_fault_runs": 0})
            for destination in (cause_group, seed):
                destination["cause_label_runs"] += 1
                destination["primary_cause_agreements"] += int(cause["matches_label"])
                if cause["status"] == "MEASURED":
                    destination["fault_label_runs"] += 1
                    destination["correct_fault_causes"] += cause["accuracy"]
                    destination["no_cause_fault_runs"] += int(cause["predicted"] is None)
    output_groups = []
    for group in groups.values():
        group["pooled_metrics"] = _metrics(group["counts"]) if group["complete_runs"] else None
        group["per_run_min_median_max"] = {k: {"min": min(v), "median": statistics.median(v), "max": max(v), "n": len(v)}
                                                for k, v in group.pop("values").items()}
        per_seed = {seed: _metrics(counts) for seed, counts in sorted(group.pop("seed_counts").items())}
        group["per_seed_metrics"] = per_seed
        group["per_seed_min_median_max"] = {}
        for metric in _metrics(group["counts"]):
            values = [metrics[metric] for metrics in per_seed.values() if metrics[metric] is not None]
            if values:
                group["per_seed_min_median_max"][metric] = {"min": min(values), "median": statistics.median(values), "max": max(values), "n": len(values)}
        observed = group.pop("scenario_seeds")
        group["scenario_seed_coverage"] = {name: {"complete_seeds": sorted(seeds), "missing_minimum_seeds": sorted({1, 2, 3} - seeds)}
                                           for name, seeds in sorted(observed.items())}
        families = {name[:3] for name, seeds in observed.items() if seeds}
        group["missing_mandatory_families"] = sorted({"T01", "T02", "T04", "T05", "T08", "T15"} - families)
        group["protocol_completion_verified"] = False
        for cause_group in group["cause_groups"].values():
            seeds = cause_group.pop("seeds")
            for destination in (cause_group, *seeds.values()):
                destination["root_cause_accuracy"] = _ratio(destination["correct_fault_causes"], destination["fault_label_runs"])
                destination["primary_cause_agreement"] = _ratio(destination["primary_cause_agreements"], destination["cause_label_runs"])
            cause_group["per_seed"] = dict(sorted(seeds.items()))
            values = [seed["root_cause_accuracy"] for seed in seeds.values() if seed["root_cause_accuracy"] is not None]
            cause_group["root_cause_per_seed_min_median_max"] = ({"min": min(values), "median": statistics.median(values),
                                                               "max": max(values), "n": len(values)} if values else None)
        output_groups.append(group)
    return {"format": "purevoting-rule-evaluation/1", "measurement": "B1 rule measurements; causes only with a declared approved mapping frozen before the run",
            "official_scenario_verification": False,
            "notes": ["No result is invented for a missing, invalid or ambiguous finding.",
                      "Incomplete runs are reported and excluded from pooled metrics; inspect coverage before any claim.",
                      "FAIL detection treats INCONCLUSIVE as no FAIL detection, not as PASS; exact results are reported separately.",
                      "Zero-denominator precision, recall and false-positive rate are null, never 100% by default.",
                      "Primary cause uses the first matching row of the frozen mapping across the selected R1-R5 findings; disagreement with the label remains an error.",
                      "Root-cause accuracy uses non-null fault labels; primary-cause agreement also reports null/no-fault labels. Different mapping hashes are not pooled.",
                      "Mapping approval references are operator supplied. The collector verifies source and exact JSON encoding from pre-run local Git commits, not the maintainer's approval or a trusted run timestamp.",
                      "Gateway body-hash consistency is not independent signature, node or deployment verification.",
                      "A template report is not B2 and has no AI accuracy/token metrics.",
                      "Seed summaries use only available complete runs; compare scenario coverage before comparing seeds or claiming protocol completion.",
                      "E1 finalization and E2 refusal require their actual transactions/API outcomes; this collector does not execute them."],
            "runs": runs, "groups": output_groups}


def markdown_report(report: dict) -> str:
    lines = ["# Rule evaluation from collected runs", "", report["measurement"], "",
             "| Run | Source | Scenario | Seed | Checkpoint | Measurement | Rule/observation label match |",
             "|---|---|---|---:|---:|---|---|"]
    for item in report["runs"]:
        r = item["run"]
        lines.append(f"| {r['run_id']} | {r['source_mode']} | {r['scenario']} | {r['seed']} | {r['judged_checkpoint']} | {item['status']} | {item['matches_label']} |")
    lines.extend(["", "## Primary causes", "", "| Run | Expected cause | Predicted cause | Measurement | Match |",
                  "|---|---|---|---|---|"])
    for item in report["runs"]:
        cause = item["primary_cause"]
        expected = cause["expected"] if CAUSE_VALIDATOR.is_valid(cause["expected"]) else "No fault cause" if cause["expected"] is None else "Unavailable"
        measured = cause["status"] in {"MEASURED", "NO_FAULT_CAUSE_LABEL"}
        predicted = (cause["predicted"] or "No cause") if measured else "NOT_EVALUATED"
        lines.append(f"| {item['run']['run_id']} | {expected} | {predicted} | {cause['status']} | {cause['matches_label']} |")
    lines.extend(["", "## Interpretation", ""] + ["- " + note for note in report["notes"]])
    lines.extend(["", "Full rule rows, label hashes, partial counts and grouped metrics are in evaluation.json and rule_results.csv.", ""])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundles", nargs="+", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        bundles = [json.loads(path.read_text(encoding="utf-8")) for path in args.bundles]
        report = evaluate_many(bundles)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        targets = [args.output_dir / name for name in ("evaluation.json", "rule_results.csv", "README.md")]
        if any(path.exists() for path in targets):
            raise ValueError("Use a new output directory; existing evaluation files are preserved")
        write_new_json(targets[0], report)
        with targets[1].open("x", encoding="utf-8", newline="") as handle:
            columns = ("run_id", "scenario", "seed", "source_mode", "rule", "expected", "actual", "measurement_status", "selection", "result_matches", "observations_match", "missing_expected_nonzero", "unexpected_nonzero", "omitted_numeric_nonzero_count")
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for result in report["runs"]:
                for rule in result["rules"]:
                    row = {k: result["run"].get(k) for k in columns[:4]} | {k: rule.get(k) for k in columns[4:]}
                    row["missing_expected_nonzero"] = ";".join(row["missing_expected_nonzero"])
                    row["unexpected_nonzero"] = ";".join(row["unexpected_nonzero"])
                    writer.writerow(row)
        with targets[2].open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown_report(report))
        complete = sum(run["status"] == "COMPLETE" for run in report["runs"])
        print(json.dumps({"runs": len(report["runs"]), "complete_measurements": complete,
                          "incomplete_measurements": len(report["runs"]) - complete,
                          "official_scenarios_verified": False}))
        return 0 if complete == len(report["runs"]) else 2
    except (OSError, ValueError, KeyError, TypeError):
        print("Evaluation failed. Check bundle format, immutable labels, run identities and output directory.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
