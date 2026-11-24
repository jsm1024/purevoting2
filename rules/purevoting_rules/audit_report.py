"""Template audit reports, with a pinned, explicitly selected B1 cause mapping.

This module never reads a network or changes an election.  It accepts evidence
references already checked by the read-only resolver, and produces the frozen
AuditReportSubmission format.  A template cause is a hypothesis, not a verified
root cause or a human review.  The bundled mapping is Harits's *proposed* PR 10
table; using it requires an explicit opt-in until an approved map is supplied.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .findings import contract_validator, new_finding_id
from .hashing import canonical
from .paths import reference_root


_BASE = "https://purevoting2.local/contracts/"
_RULES = frozenset({"R1", "R2", "R3", "R4", "R5"})
_REASONS = frozenset({"BATCH_NOT_ANCHORED", "NODE_UNAVAILABLE", "VIEW_UNAVAILABLE", "KEY_NOT_REVEALED", "OTHER"})
_ABORT_REASONS = frozenset({"STEP_LIMIT", "TOKEN_BUDGET", "TIMEOUT", "TOOL_ERROR", "MODEL_ERROR"})
_FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
_KEY = re.compile(r"[a-z][a-z0-9_]{0,99}\Z")
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


@dataclass(frozen=True)
class MappingRow:
    rule_id: str
    result: str
    match: str
    keys: tuple[str, ...]
    cause_code: str
    explanation: str


@dataclass(frozen=True)
class CauseMatch:
    cause_code: str
    deciding_keys: tuple[str, ...]
    explanation: str
    row_index: int


@dataclass(frozen=True)
class B1Mapping:
    version: str
    status: str
    source_commit: str
    source_repository: str
    source_path: str
    source_url: str
    source_author: str
    review_reference: str | None
    fingerprint: str
    rows: tuple[MappingRow, ...]

    @property
    def provenance(self) -> dict[str, Any]:
        """Small, serializable provenance for a worker manifest or policy hash."""
        return {
            "version": self.version, "status": self.status,
            "source_commit": self.source_commit,
            "source_repository": self.source_repository,
            "source_path": self.source_path, "source_url": self.source_url,
            "source_author": self.source_author,
            "review_reference": self.review_reference,
            "sha256": self.fingerprint,
        }


def _object(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Invalid B1 mapping object fields")
    return value


def _text(value: Any, *, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError("Invalid B1 mapping text")
    return value


def _reference(value: Any) -> str:
    value = _text(value, maximum=1000)
    # References are provenance, never addresses fetched by the agent.  Requiring
    # a clean HTTPS reference avoids embedding credentials or query tokens.
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query:
        raise ValueError("A B1 provenance reference must be an HTTPS URL without credentials or a query")
    return value


def load_mapping(path: Path | str | None = None) -> B1Mapping:
    """Load a local, versioned mapping.  No approval is inferred from a URL.

    An external ``approved`` file must identify a source commit and a review
    reference for that same commit.  Those remain operator-supplied provenance;
    this function does not independently verify anyone's approval.
    """
    if path is None:
        path = Path(__file__).resolve().parents[1] / "config" / "b1-cause-map.pr10.json"
    path = Path(path)
    with path.open(encoding="utf-8") as stream:
        raw = json.load(stream)
    _object(raw, {"schema_version", "version", "status", "source", "rows"}, {"approval"})
    if raw["schema_version"] != "1" or not re.fullmatch(r"\d+\.\d+\.\d+", _text(raw["version"])):
        raise ValueError("Unsupported B1 mapping schema/version")
    if _text(raw["status"]) not in {"proposed", "approved"}:
        raise ValueError("B1 mapping status must be proposed or approved")
    source = _object(raw["source"], {"repository", "commit", "path", "url", "author"})
    source_repository = _reference(source["repository"])
    source_url = _reference(source["url"])
    source_path = _text(source["path"], maximum=200)
    if source_path.startswith(("/", "\\")) or ".." in source_path.split("/") or "\\" in source_path:
        raise ValueError("B1 source path must be a repository-relative path")
    source_author = _text(source["author"], maximum=100)
    if not isinstance(source["commit"], str) or not _FULL_SHA.fullmatch(source["commit"]):
        raise ValueError("B1 mapping must pin a full source commit")
    review_reference = None
    if raw["status"] == "approved":
        approval = _object(raw.get("approval"), {"source_commit", "reference"})
        if approval["source_commit"] != source["commit"]:
            raise ValueError("B1 approval provenance belongs to another source commit")
        review_reference = _reference(approval["reference"])
    elif "approval" in raw:
        raise ValueError("A proposed B1 mapping cannot claim approval metadata")
    common = json.loads((reference_root() / "contracts" / "common.schema.json").read_text(encoding="utf-8"))
    causes = set(common["$defs"]["CauseCode"]["enum"])
    raw_rows = raw["rows"]
    if not isinstance(raw_rows, list) or not 1 <= len(raw_rows) <= 100:
        raise ValueError("B1 mapping must contain between 1 and 100 ordered rows")
    rows: list[MappingRow] = []
    for row in raw_rows:
        _object(row, {"rule_id", "result", "match", "keys", "cause_code", "explanation"})
        rule = _text(row["rule_id"])
        result = _text(row["result"])
        match = _text(row["match"])
        keys = row["keys"]
        if rule not in _RULES | {"*"} or result not in {"FAIL", "INCONCLUSIVE"}:
            raise ValueError("Invalid B1 row rule/result")
        if match not in {"positive_any", "r3_other_fail", "reason_any"}:
            raise ValueError("Unsupported B1 row matcher")
        if not isinstance(keys, list) or not keys or any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
            raise ValueError("B1 row keys must be a nonempty unique string list")
        if match == "reason_any":
            if result != "INCONCLUSIVE" or not set(keys) <= _REASONS:
                raise ValueError("Invalid B1 inconclusive matcher")
        elif result != "FAIL" or rule == "*" or any(not _KEY.fullmatch(key) for key in keys):
            raise ValueError("Invalid B1 failure matcher")
        if match == "r3_other_fail" and (rule != "R3" or keys != ["count_relationship_violations"]):
            raise ValueError("The R3 other-failure matcher has fixed semantics")
        if _text(row["cause_code"]) not in causes:
            raise ValueError("B1 mapping uses an unknown CauseCode")
        explanation = _text(row["explanation"], maximum=1000)
        rows.append(MappingRow(rule, result, match, tuple(keys), row["cause_code"], explanation))
    fingerprint = hashlib.sha256(canonical(raw)).hexdigest()
    return B1Mapping(raw["version"], raw["status"], source["commit"], source_repository,
                     source_path, source_url, source_author, review_reference, fingerprint, tuple(rows))


def select_cause(
    finding: dict[str, Any], mapping: B1Mapping, *, allow_proposed_mapping: bool = False,
) -> CauseMatch | None:
    """Apply the declared first-match order; positive counters are integers.

    Counts, ID lists, strings, booleans, and unknown keys never become causes
    through Python truthiness.  PASS has no cause.  The R3 fallback checks an
    actual non-tally entry in ``count_relationship_violations``.
    """
    if type(allow_proposed_mapping) is not bool:
        raise ValueError("allow_proposed_mapping must be an explicit boolean")
    if mapping.status == "proposed" and not allow_proposed_mapping:
        return None
    result = finding.get("result")
    rule_id = finding.get("rule_id")
    if not isinstance(result, str) or result not in {"FAIL", "INCONCLUSIVE"} or not isinstance(rule_id, str):
        return None
    observed = finding.get("observed")
    if not isinstance(observed, dict):
        return None
    for index, row in enumerate(mapping.rows):
        if row.rule_id not in {rule_id, "*"} or row.result != result:
            continue
        if row.match == "reason_any":
            reason = finding.get("inconclusive_reason")
            matched = (reason,) if reason in row.keys else ()
        elif row.match == "r3_other_fail":
            violations = observed.get("count_relationship_violations")
            matched = row.keys if (isinstance(violations, list) and any(
                isinstance(value, str) and value and value != "tally_counts" for value in violations
            )) else ()
        else:
            matched = tuple(key for key in row.keys if type(observed.get(key)) is int and observed[key] > 0)
        if matched:
            return CauseMatch(row.cause_code, tuple(matched), row.explanation, index)
    return None


def _validate_finding(finding: dict[str, Any]) -> None:
    canonical(finding)
    contract_validator({"anyOf": [
        {"$ref": _BASE + "finding.schema.json#/$defs/FindingSubmission"},
        {"$ref": _BASE + "finding.schema.json#/$defs/Finding"},
    ]}, filename="audit-finding-validation.json").validate(finding)


def validate_report(report: dict[str, Any]) -> None:
    canonical(report)
    contract_validator({"$ref": _BASE + "audit-report.schema.json#/$defs/AuditReportSubmission"}, filename="audit-report-validation.json").validate(report)


def _clean_refs(refs: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    validator = contract_validator({"$ref": _BASE + "common.schema.json#/$defs/EvidenceRef"}, filename="audit-reference-validation.json")
    out: dict[tuple[str, str], dict[str, str]] = {}
    for item in refs:
        validator.validate(item)
        # Arbitrary evidence notes and summaries are not copied into reports.
        clean = {"kind": item["kind"], "ref": item["ref"]}
        out[(clean["kind"], clean["ref"])] = clean
    return [out[key] for key in sorted(out)]


def required_evidence_refs(finding: dict[str, Any]) -> list[dict[str, str]]:
    """The finding plus its own evidence, deduplicated without note text."""
    _validate_finding(finding)
    return _clean_refs([{"kind": "finding", "ref": finding["finding_id"]}, *finding["evidence_refs"]])


def new_report_id(finding_id: str | None = None) -> str:
    # New reports get new IDs; the durable journal owns idempotency and retries.
    # A supplied finding ID is useful only for explicit reproducible fixtures.
    if finding_id is None:
        return "rpt_" + new_finding_id()[4:]
    contract_validator({"$ref": _BASE + "common.schema.json#/$defs/FindingId"}, filename="audit-finding-id-validation.json").validate(finding_id)
    value = int.from_bytes(hashlib.sha256(("template-report:1:" + finding_id).encode("ascii")).digest()[:16], "big")
    chars = ["0"] * 26
    for index in range(25, -1, -1):
        chars[index] = _CROCKFORD[value & 31]
        value >>= 5
    return "rpt_" + "".join(chars)


def build_report(
    finding: dict[str, Any], *, verified_refs: Iterable[dict[str, Any]],
    tool_calls: list[dict[str, Any]], mapping: B1Mapping,
    allow_proposed_mapping: bool = False, report_id: str | None = None,
    created_at: str | None = None, duration_ms: int = 0,
    abort_reason: str | None = None, extra_limitations: str = "",
) -> dict[str, Any]:
    """Build a file report from validated inputs, never from untrusted prose.

    The caller must genuinely resolve ``verified_refs``; this pure function can
    check their coverage and schema, not attest to a remote fetch.  An omitted
    required reference makes the report ABORTED, even with a matching cause.
    """
    if type(allow_proposed_mapping) is not bool:
        raise ValueError("allow_proposed_mapping must be an explicit boolean")
    _validate_finding(finding)
    if finding["result"] not in {"FAIL", "INCONCLUSIVE"}:
        raise ValueError("Only FAIL or INCONCLUSIVE findings need audit reports")
    if not isinstance(tool_calls, list) or len(tool_calls) > 20:
        raise ValueError("A report trace may contain at most 20 read-only tool calls")
    if type(duration_ms) is not int or duration_ms < 0:
        raise ValueError("duration_ms must be a nonnegative integer")
    if abort_reason is not None and abort_reason not in _ABORT_REASONS:
        raise ValueError("Unknown audit abort reason")
    if not isinstance(extra_limitations, str) or len(extra_limitations) > 400:
        raise ValueError("Extra limitations must be a short caller-controlled message")
    if re.search(r"evr_[0-9A-HJKMNP-TV-Z]{26}|\b[0-9a-fA-F]{64}\b|private[_ -]?key", extra_limitations):
        raise ValueError("Extra limitations must not contain sensitive identifiers or key material")

    required = required_evidence_refs(finding)
    verified = _clean_refs(verified_refs)
    present = {(ref["kind"], ref["ref"]) for ref in verified}
    complete = all((ref["kind"], ref["ref"]) in present for ref in required)
    if not complete and abort_reason is None:
        abort_reason = "TOOL_ERROR"
    clean_calls = []
    for call in tool_calls:
        if not isinstance(call, dict) or call.get("tool") == "submit_report":
            raise ValueError("Template evidence traces contain read-only tools only")
        # API arguments can contain pseudonymous row hashes.  Retain counts and
        # timing, not arbitrary arguments, response payloads, or exception text.
        clean_calls.append({key: copy.deepcopy(call[key]) for key in ("tool", "called_at", "ok", "result_count") if key in call})
    if any(call.get("ok") is False for call in clean_calls) and abort_reason is None:
        abort_reason = "TOOL_ERROR"

    match = select_cause(finding, mapping, allow_proposed_mapping=allow_proposed_mapping)
    status = "ABORTED" if abort_reason else "COMPLETED" if match else "ESCALATED"
    limitation_parts = [
        "Generated without AI from the rule-to-cause table; provider none means not AI. "
        "A mapped cause is a predefined hypothesis, not proof of intent or a verified root cause. "
        "The report is advisory and does not decide findings, reviews, or finalization. "
        "Core report storage and its report screen are future work; this is a file report.",
        f"B1 source commit {mapping.source_commit}, mapping version {mapping.version}, status {mapping.status}.",
    ]
    if mapping.status == "proposed":
        limitation_parts.append(
            "The proposed mapping was used by explicit operator opt-in; acceptance of the final evaluation baseline remains pending."
            if allow_proposed_mapping else
            "The proposed mapping was not enabled; no cause is assigned pending an approved mapping or explicit opt-in."
        )
    else:
        limitation_parts.append("Approved status and review reference are operator-supplied provenance, not independently verified approval.")
    if not complete:
        limitation_parts.append("At least one required evidence reference could not be verified; no cause hypothesis is issued.")
    if status == "ESCALATED" and (mapping.status == "approved" or allow_proposed_mapping):
        limitation_parts.append("No mapping row matched; human investigation is required.")
    if extra_limitations:
        limitation_parts.append(extra_limitations)
    report: dict[str, Any] = {
        "report_id": report_id or new_report_id(),
        "schema_version": "1", "finding_id": finding["finding_id"],
        "election_id": finding["election_id"],
        "created_at": created_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "model": {"provider": "none", "name": "template", "prompt_version": "1.0.0"},
        "hypotheses": [], "risk_level": finding["severity"],
        "additional_checks": ["Have an authorized reviewer inspect the cited finding and its checkpoint evidence."],
        "recommended_actions": [{
            "action": "Investigate the finding and confirm its cause before choosing a human response.",
            "urgency": "IMMEDIATE" if finding["trigger"] == "TALLY" else "BEFORE_TALLY",
        }],
        "limitations": " ".join(limitation_parts),
        "trace": {"steps": len(clean_calls), "tool_calls": clean_calls, "duration_ms": duration_ms},
    }
    if abort_reason:
        report["abort_reason"] = abort_reason
    elif match:
        # Only fixed mapping text and fixed observed-key names enter prose.  The
        # original finding summary and observed values are deliberately absent.
        report["hypotheses"] = [{
            "cause_code": match.cause_code,
            "explanation": f"B1 maps {finding['rule_id']} {finding['result']} using {', '.join(match.deciding_keys)}: {match.explanation}",
            "likelihood": "MEDIUM" if finding["result"] == "FAIL" else "LOW",
            "evidence_refs": required,
        }]
    validate_report(report)
    return report
