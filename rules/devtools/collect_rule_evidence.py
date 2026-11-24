"""Export an existing judged checkpoint using GET requests only.

This collector does not create an election, inject a fault, finalize an election,
or certify that the operator-declared environment is a real PureChain deployment.
It preserves labels from an immutable Git commit and never writes ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "rules"))

from purevoting_rules.engine import OBSERVED_KEYS
from purevoting_rules.audit_report import B1Mapping, load_mapping, select_cause
from purevoting_rules.findings import contract_validator
from purevoting_rules.hashing import Hc, canonical

FORMAT = "purevoting-rule-run/1"
SOURCE_MODES = ("real-declared", "local-development", "mock")
SHA = re.compile(r"^[0-9a-f]{40}$")
ELECTION = re.compile(r"^elc_[0-9A-HJKMNP-TV-Z]{26}$")
SCENARIO = re.compile(r"^T[0-9]{2}[a-z]?(?:-[a-z0-9]+)*$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
COUNTERS = set().union(*OBSERVED_KEYS.values()) | {
    "tally_invalid_set_mismatches", "tally_share_failures", "tally_result_mismatches",
    "tally_count_mismatches", "tally_root_mismatches", "tally_result_hash_mismatches",
    "tally_final_checkpoint_mismatches", "chain_anchor_ids_missing_from_gateway",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string with a timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp needs an explicit timezone")
    return parsed.astimezone(timezone.utc)


def _git(root: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if done.returncode:
        raise ValueError("The requested committed Git source is unavailable")
    return done.stdout


def committed_label(root: Path, scenario: str, commit: str, started_at: str) -> dict:
    """Read committed bytes, never a mutable working-tree expected.json."""
    if not SCENARIO.fullmatch(scenario) or not SHA.fullmatch(commit):
        raise ValueError("Use a scenario identifier and full 40-character label commit")
    path = f"tests/scenarios/{scenario}/expected.json"
    try:
        raw = _git(root, "show", f"{commit}:{path}")
    except ValueError:
        return {"available": False, "path": path, "commit": commit,
                "reason": "No label at this committed path; evaluation is unavailable"}
    label = json.loads(raw.decode("utf-8"))
    if not isinstance(label, dict) or label.get("scenario") != scenario:
        raise ValueError("Committed label belongs to a different scenario")
    committed_at = _git(root, "show", "-s", "--format=%cI", commit).decode().strip()
    return {"available": True, "path": path, "commit": commit,
            "commit_time": committed_at, "sha256": hashlib.sha256(raw).hexdigest(),
            "precommitted": parse_time(committed_at) <= parse_time(started_at),
            "content_utf8": raw.decode("utf-8"), "body": label}


def frozen_mapping(path: Path | str | None, root: Path, started_at: str,
                   mapping_commit: str | None = None) -> tuple[B1Mapping | None, dict]:
    """Require declared approval and both source and exact encoding before the run.

    Approval references remain operator supplied, not independently authenticated.
    A rejected or unavailable mapping does not block collecting rule results.
    """
    if path is None:
        return None, {"available": False, "reason": "MAPPING_NOT_SUPPLIED"}
    try:
        mapping = load_mapping(path)
    except (OSError, ValueError, TypeError, KeyError):
        return None, {"available": False, "reason": "MAPPING_INVALID_OR_APPROVAL_STALE"}
    # Keep the non-sensitive manifest so the offline evaluator can verify its
    # fingerprint and the ordering used to select a primary cause.
    manifest = {
        "schema_version": "1", "version": mapping.version, "status": mapping.status,
        "source": {"repository": mapping.source_repository, "commit": mapping.source_commit,
                   "path": mapping.source_path, "url": mapping.source_url, "author": mapping.source_author},
        "rows": [{"rule_id": row.rule_id, "result": row.result, "match": row.match,
                  "keys": list(row.keys), "cause_code": row.cause_code, "explanation": row.explanation}
                 for row in mapping.rows],
    }
    if mapping.status == "approved":
        manifest["approval"] = {"source_commit": mapping.source_commit, "reference": mapping.review_reference}
    provenance = mapping.provenance | {"manifest": manifest, "available": False, "approval_is_operator_supplied": True,
                                      "approval_independently_verified": False}
    if mapping.status != "approved":
        return None, provenance | {"reason": "MAPPING_NOT_APPROVED"}
    try:
        source = _git(root, "show", f"{mapping.source_commit}:{mapping.source_path}")
        committed_at = _git(root, "show", "-s", "--format=%cI", mapping.source_commit).decode().strip()
    except (ValueError, UnicodeDecodeError):
        return None, provenance | {"reason": "MAPPING_SOURCE_UNAVAILABLE"}
    provenance |= {"source_commit_time": committed_at, "source_content_sha256": hashlib.sha256(source).hexdigest()}
    if parse_time(committed_at) > parse_time(started_at):
        return None, provenance | {"reason": "MAPPING_SOURCE_COMMITTED_AFTER_RUN_START"}
    if not isinstance(mapping_commit, str) or not SHA.fullmatch(mapping_commit):
        return None, provenance | {"reason": "MAPPING_ENCODING_NOT_PINNED"}
    try:
        encoding_path = Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None, provenance | {"reason": "MAPPING_ENCODING_NOT_IN_REPOSITORY"}
    try:
        encoded = _git(root, "show", f"{mapping_commit}:{encoding_path}")
        encoding_time = _git(root, "show", "-s", "--format=%cI", mapping_commit).decode().strip()
        # Git may store LF while a Windows checkout uses CRLF (or vice versa).
        # Permit only that representation change; even other whitespace edits
        # still differ. The original committed bytes remain authoritative below.
        checkout = Path(path).read_bytes()
        if (encoded.replace(b"\r\n", b"\n") != checkout.replace(b"\r\n", b"\n") or
                hashlib.sha256(canonical(json.loads(encoded))).hexdigest() != mapping.fingerprint):
            return None, provenance | {"reason": "MAPPING_ENCODING_DIFFERS_FROM_PINNED_COMMIT"}
    except (OSError, ValueError, UnicodeDecodeError):
        return None, provenance | {"reason": "MAPPING_ENCODING_COMMIT_UNAVAILABLE"}
    provenance |= {"encoding_commit": mapping_commit, "encoding_path": encoding_path,
                   "encoding_commit_time": encoding_time, "encoding_content_sha256": hashlib.sha256(encoded).hexdigest(),
                   "encoding_content_utf8": encoded.decode("utf-8")}
    if parse_time(encoding_time) > parse_time(started_at):
        return None, provenance | {"reason": "MAPPING_ENCODING_COMMITTED_AFTER_RUN_START"}
    return mapping, provenance | {"available": True, "reason": "APPROVED_MAPPING_AND_SOURCE_FROZEN_BEFORE_RUN"}


def safe_base_url(value: str) -> str:
    parts = urlsplit(value)
    parts.port  # Reject malformed or out-of-range ports before constructing a client.
    if (parts.scheme not in {"http", "https"} or not parts.hostname or
            parts.username is not None or parts.password is not None or
            parts.query or parts.fragment or parts.path not in {"", "/"}):
        raise ValueError("Service URLs must be HTTP(S) origins without credentials, paths or query strings")
    return value.rstrip("/")


class ReadError(RuntimeError):
    """Deliberately carries no remote URL, key, response body or evidence ID."""


class ReadOnlyServices:
    def __init__(self, core_url: str, gateway_url: str, key: str, *, transport=None,
                 max_pages: int = 100, max_response_bytes: int = 8_000_000):
        if not key or "\r" in key or "\n" in key:
            raise ValueError("Set a non-empty AGENT_KEY in the process environment")
        self.origins = {"core": safe_base_url(core_url), "gateway": safe_base_url(gateway_url)}
        self.max_pages = max_pages
        self.max_response_bytes = max_response_bytes
        self.client = httpx.Client(timeout=10, follow_redirects=False, trust_env=False,
                                   transport=transport, headers={"X-Service-Key": key})

    def close(self):
        self.client.close()

    def get(self, service: str, path: str, params: dict | None = None) -> dict:
        allowed = {"core": {"/internal/v1/elections", "/internal/v1/checkpoints", "/internal/v1/findings"},
                   "gateway": {"/v1/chain", "/v1/finding-records"}}
        state_path = re.fullmatch(r"/v1/elections/(elc_[0-9A-HJKMNP-TV-Z]{26})/state", path)
        if service not in allowed or (path not in allowed[service] and not (service == "gateway" and state_path)):
            raise ValueError("Collector endpoint is outside its read-only allowlist")
        try:
            with self.client.stream("GET", self.origins[service] + path, params=params) as response:
                if response.status_code != 200:
                    raise ReadError(f"{service} returned HTTP {response.status_code}")
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise ReadError("Response exceeded the collection limit")
                    chunks.append(chunk)
                data = json.loads(b"".join(chunks))
        except (httpx.HTTPError, ValueError, TypeError):
            raise ReadError(f"{service} read failed") from None
        if not isinstance(data, dict):
            raise ReadError("Expected an object response")
        return data

    def pages(self, service: str, path: str, params: dict) -> list:
        items, cursor, seen = [], None, set()
        for _ in range(self.max_pages):
            page = self.get(service, path, params | {"limit": 500, **({"cursor": cursor} if cursor else {})})
            if not isinstance(page.get("items"), list) or "next_cursor" not in page:
                raise ReadError("Incomplete paginated response")
            items.extend(page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                return items
            if not isinstance(cursor, str) or not cursor or cursor in seen or len(cursor) > 4096:
                raise ReadError("Invalid or repeated pagination cursor")
            seen.add(cursor)
        raise ReadError("Pagination limit reached; collection is incomplete")


def reduce_findings(findings: list, records: list, *, election_id: str, checkpoint: int,
                    checkpoint_event_id: str | None, observed_keys: set[str],
                    mapping: B1Mapping | None = None) -> tuple[list, int]:
    """Check immutable bodies before retaining only non-sensitive decision metadata.

    MATCHED means a schema-valid Gateway record binds the Core body hash and
    finding metadata. It is not an independent node read or signature check.
    """
    stored = contract_validator({"$ref": "finding.schema.json#/$defs/Finding"}, filename="evaluation-finding-wrapper.schema.json")
    event_schema = contract_validator({"$ref": "ledger-events.schema.json"}, filename="evaluation-event-wrapper.schema.json")
    by_id = {}
    for record in records:
        if isinstance(record, dict):
            by_id.setdefault(record.get("finding_id"), []).append(record)
    results, invalid = [], 0
    for finding in findings:
        try:
            stored.validate(finding)
            if finding["election_id"] != election_id or finding["checkpoint"] != checkpoint:
                raise ValueError("Different election/checkpoint")
            submission = {k: v for k, v in finding.items() if k not in {"review", "recorded_event_id", "evidence_check"}}
            body_hash = Hc(submission)
            summary = {k: finding[k] for k in ("finding_id", "election_id", "rule_id", "rule_version", "result", "checkpoint", "checked_at")}
            summary["body_sha256"] = body_hash
            summary["evidence_ref_count"] = len(finding["evidence_refs"])
            summary["evidence_check_status_from_core"] = finding["evidence_check"]["status"]
            summary["inconclusive_reason"] = finding.get("inconclusive_reason")
            cause = select_cause(finding, mapping) if mapping is not None and mapping.status == "approved" else None
            summary["predicted_cause"] = ({"cause_code": cause.cause_code, "row_index": cause.row_index,
                                          "mapping_sha256": mapping.fingerprint} if cause else None)
            # Numeric counters only; never persist voter identifiers, evidence refs,
            # arbitrary descriptions or cryptographic key material.
            summary["observed"] = {k: v for k, v in finding["observed"].items()
                                    if k in COUNTERS | observed_keys and (v is None or type(v) in (int, bool))}
            # Do not silently hide an unexpected numeric nonzero field when
            # comparing the label's exact set. Unknown field names/values still
            # stay private; their count is enough to record a label mismatch.
            summary["omitted_numeric_nonzero_count"] = sum(
                isinstance(value, (int, float)) and bool(value)
                for key, value in finding["observed"].items() if key not in summary["observed"]
            )
            summary["binding"] = {"matched": False, "status": "RECORD_MISSING", "signature_verified": False,
                                  "independent_node_verified": False}
            matches = by_id.get(finding["finding_id"], [])
            if len(matches) != 1:
                summary["binding"]["status"] = "RECORD_MISSING" if not matches else "RECORD_AMBIGUOUS"
            else:
                record = matches[0]
                event = record["recorded"]
                event_schema.validate(event)
                payload = event["payload"]
                expected = {"finding_id": finding["finding_id"], "rule_id": finding["rule_id"],
                            "result": finding["result"], "finding_checkpoint": checkpoint,
                            "finding_hash": body_hash}
                checks = (event["type"] == "FINDING_RECORDED", event["election_id"] == election_id,
                          event["event_id"] == finding["recorded_event_id"],
                          finding["data_as_of"]["checkpoint_event_id"] == checkpoint_event_id,
                          all(payload.get(k) == v for k, v in expected.items()),
                          event["payload_hash"] == Hc(payload))
                if not all(checks):
                    summary["binding"]["status"] = "RECORD_MISMATCH"
                elif event["anchor"]["status"] != "ANCHORED":
                    summary["binding"]["status"] = "RECORD_NOT_ANCHORED"
                else:
                    summary["binding"].update({"matched": True, "status": "MATCHED"})
                status = record.get("contract_status")
                if status not in {"NOT_REQUIRED", "PENDING", "RESOLVED", "SUPERSEDED", "CONFIRMED_ISSUE"}:
                    summary["binding"].update({"matched": False, "status": "INVALID_RECORD_STATUS"})
                summary["contract_status_from_gateway"] = status
            results.append(summary)
        except Exception:
            # Remote objects are untrusted; exception messages can contain raw data.
            invalid += 1
    return results, invalid


def collect_bundle(services: ReadOnlyServices, *, election_id: str, checkpoint: int,
                   run_id: str, scenario: str, seed: int, configuration: str,
                   started_at: str, source_mode: str, deployment_commit: str,
                   label: dict, collector_commit: str, collected_at: str | None = None,
                   mapping: B1Mapping | None = None, mapping_provenance: dict | None = None) -> dict:
    if not ELECTION.fullmatch(election_id) or type(checkpoint) is not int or checkpoint < 0:
        raise ValueError("Specify a valid election and explicit judged checkpoint")
    if not RUN_ID.fullmatch(run_id) or not SCENARIO.fullmatch(scenario) or type(seed) is not int or seed < 0:
        raise ValueError("Invalid run metadata")
    if source_mode not in SOURCE_MODES or configuration not in {"demo", "evaluation"}:
        raise ValueError("Explicit source mode and configuration are required")
    if not SHA.fullmatch(deployment_commit) or not SHA.fullmatch(collector_commit):
        raise ValueError("Use full deployment and collector commit IDs")
    captured = collected_at or utc_now()
    if parse_time(started_at) > parse_time(captured):
        raise ValueError("Run start cannot be after collection")
    bundle = {
        "format": FORMAT, "collected_at": captured,
        "run": {"run_id": run_id, "scenario": scenario, "seed": seed,
                "configuration": configuration, "started_at": started_at,
                "source_mode": source_mode, "declared_deployment_commit": deployment_commit,
                "election_id": election_id, "judged_checkpoint": checkpoint},
        "provenance": {"collector_commit": collector_commit, "label": label,
                       "b1_mapping": mapping_provenance or {"available": False, "reason": "MAPPING_NOT_SUPPLIED"},
                       "source_is_operator_declared": True,
                       "independent_chain_verification": False},
        "collection": {"complete": True, "errors": []},
        "election": None, "checkpoint": None, "findings": [],
        "gateway_chain": None, "gateway_state": None,
        "end_to_end": {"scenario_execution": "NOT_VERIFIED", "receipt_anchoring": "NOT_VERIFIED",
                       "finalization_transaction": "NOT_VERIFIED", "finalization_refusal": "NOT_VERIFIED"},
    }

    def read(name, action):
        try:
            return action()
        except (ReadError, ValueError, KeyError, TypeError):
            bundle["collection"]["complete"] = False
            bundle["collection"]["errors"].append(name + "_UNAVAILABLE_OR_INVALID")
            return None

    elections = read("ELECTIONS", lambda: services.get("core", "/internal/v1/elections"))
    if elections is not None:
        matches = [e for e in elections.get("items", []) if isinstance(e, dict) and e.get("election_id") == election_id]
        if len(matches) == 1:
            fields = ("election_id", "status", "open_checkpoint", "last_committed_checkpoint", "close_final_checkpoint", "tally_checkpoint")
            bundle["election"] = {k: matches[0].get(k) for k in fields}
        else:
            bundle["collection"]["complete"] = False
            bundle["collection"]["errors"].append("ELECTION_NOT_UNIQUE_OR_MISSING")
    checkpoints = read("CHECKPOINTS", lambda: services.get("core", "/internal/v1/checkpoints", {"election_id": election_id}))
    if checkpoints is not None:
        matches = [c for c in checkpoints.get("items", []) if isinstance(c, dict) and c.get("checkpoint") == checkpoint]
        if len(matches) == 1:
            fields = ("checkpoint", "reason", "event_id", "ledger_status")
            bundle["checkpoint"] = {k: matches[0].get(k) for k in fields}
        else:
            bundle["collection"]["complete"] = False
            bundle["collection"]["errors"].append("CHECKPOINT_NOT_UNIQUE_OR_MISSING")
    findings = read("FINDINGS", lambda: services.pages("core", "/internal/v1/findings", {"election_id": election_id}))
    records = read("FINDING_RECORDS", lambda: services.pages("gateway", "/v1/finding-records", {"election_id": election_id}))
    if findings is not None:
        # The checkpoint is fixed before evaluation, and raw objects live only in memory.
        judged = [f for f in findings if isinstance(f, dict) and f.get("checkpoint") == checkpoint]
        counter_keys = set().union(*(label.get("body", {}).get("observed_nonzero", {}).values()))
        reduced, invalid = reduce_findings(judged, records or [], election_id=election_id,
            checkpoint=checkpoint, checkpoint_event_id=(bundle["checkpoint"] or {}).get("event_id"),
            observed_keys=counter_keys, mapping=mapping)
        bundle["findings"] = reduced
        if invalid:
            bundle["collection"]["complete"] = False
            bundle["collection"]["errors"].append("INVALID_FINDING_OR_RECORD")
        bundle["collection"]["invalid_objects"] = invalid
    chain = read("CHAIN", lambda: services.get("gateway", "/v1/chain"))
    if chain is not None:
        # RPC URLs can contain credentials; they are neither followed nor saved.
        bundle["gateway_chain"] = {k: chain.get(k) for k in ("platform", "chain_id", "contract_address", "interface_version", "confirmation_depth")}
    state = read("CHAIN_STATE", lambda: services.get("gateway", f"/v1/elections/{election_id}/state"))
    if state is not None:
        bundle["gateway_state"] = {k: state.get(k) for k in ("election_id", "status", "block_number", "last_checkpoint", "last_core_seq")}
    return bundle


def write_new_json(path: Path, body: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Evidence is append-only by filename: refuse to replace a previous run.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(body, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("election-id", "run-id", "scenario", "started-at", "deployment-commit", "output"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--checkpoint", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--configuration", choices=("demo", "evaluation"), required=True)
    parser.add_argument("--source-mode", choices=SOURCE_MODES, required=True)
    parser.add_argument("--label-commit", help="Full commit containing Harits's label; defaults to checkout HEAD")
    parser.add_argument("--b1-mapping", type=Path, help="Optional owner-approved, frozen B1 mapping JSON; proposed maps never produce evaluation cause metrics")
    parser.add_argument("--b1-mapping-commit", help="Full pre-run commit containing the exact --b1-mapping JSON inside this repository")
    parser.add_argument("--core", default=os.getenv("CORE_URL"), help="Actual Core origin, or set CORE_URL")
    parser.add_argument("--gateway", default=os.getenv("GATEWAY_URL"), help="Actual Gateway origin, or set GATEWAY_URL")
    args = parser.parse_args(argv)
    if not args.core or not args.gateway:
        print("Set CORE_URL and GATEWAY_URL, or supply --core and --gateway with the actual service origins.", file=sys.stderr)
        return 2
    services = None
    try:
        head = _git(ROOT, "rev-parse", "HEAD").decode().strip()
        label = committed_label(ROOT, args.scenario, args.label_commit or head, args.started_at)
        mapping, mapping_provenance = frozen_mapping(args.b1_mapping, ROOT, args.started_at, args.b1_mapping_commit)
        services = ReadOnlyServices(args.core, args.gateway, os.environ.get("AGENT_KEY", ""))
        result = collect_bundle(services, election_id=args.election_id, checkpoint=args.checkpoint,
            run_id=args.run_id, scenario=args.scenario, seed=args.seed, configuration=args.configuration,
            started_at=args.started_at, source_mode=args.source_mode, deployment_commit=args.deployment_commit,
            label=label, collector_commit=head, mapping=mapping, mapping_provenance=mapping_provenance)
        write_new_json(Path(args.output), result)
        print(json.dumps({"saved": True, "collection_complete": result["collection"]["complete"],
                          "findings": len(result["findings"]), "official_run_verified": False}))
        return 0 if result["collection"]["complete"] else 2
    except (OSError, ValueError, json.JSONDecodeError, ReadError):
        print("Evidence collection failed. Check identifiers, committed label, output path, and service configuration.", file=sys.stderr)
        return 2
    finally:
        if services is not None:
            services.close()


if __name__ == "__main__":
    raise SystemExit(main())
