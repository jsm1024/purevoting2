"""Template report service: read findings, verify references, publish local files.

Run with python -m purevoting_rules.audit_agent. All network requests are reads;
the agent cannot change elections, findings, reviews or finalization conditions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .audit_evidence import EvidenceClient, EvidenceError, finding_fingerprint
from .audit_report import build_report, load_mapping
from .audit_store import FindingConflict, ReportStore
from .hashing import canonical


def _timestamp(milliseconds: int) -> str:
    return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AuditPollResult:
    discovered: int = 0
    skipped: int = 0
    generated: int = 0
    completed: int = 0
    escalated: int = 0
    aborted: int = 0
    read_errors: int = 0
    conflicts: int = 0
    retry_scheduled: int = 0


class AuditWorker:
    def __init__(self, inputs, store, mapping, *, allow_proposed_mapping=False, max_attempts=3,
                 max_reports_per_poll=100, retry_seconds=30, now=time.time, heartbeat=lambda: None):
        if (type(allow_proposed_mapping) is not bool
                or type(max_attempts) is not int or not 1 <= max_attempts <= 20
                or type(max_reports_per_poll) is not int or not 1 <= max_reports_per_poll <= 1000
                or type(retry_seconds) is not int or not 1 <= retry_seconds <= 600):
            raise ValueError("Invalid audit worker bounds")
        self.inputs, self.store, self.mapping = inputs, store, mapping
        self.allow_proposed_mapping = allow_proposed_mapping
        self.max_attempts, self.max_reports_per_poll, self.retry_seconds = max_attempts, max_reports_per_poll, retry_seconds
        self.now, self.heartbeat = now, heartbeat
        self.policy = hashlib.sha256(canonical({"version": "1.0.0", "mapping": mapping.fingerprint,
                                               "allow_proposed_mapping": allow_proposed_mapping})).hexdigest()

    def poll(self, *, election_id=None):
        result = AuditPollResult()
        try:
            for listed in self.inputs.iter_findings(election_id=election_id):
                self.heartbeat()
                result.discovered += 1
                if listed.get("result") not in {"FAIL", "INCONCLUSIVE"}:
                    result.skipped += 1
                    continue
                now_ms = int(self.now() * 1000)
                fingerprint = finding_fingerprint(listed)
                try:
                    first_seen_ms = self.store.observe(listed["finding_id"], fingerprint, now_ms)
                except FindingConflict:
                    result.conflicts += 1
                    continue
                if not self.store.due(listed["finding_id"], self.policy, now_ms, self.max_attempts):
                    result.skipped += 1
                    continue
                session = self.inputs.begin(listed["election_id"], listed["checkpoint"], max_steps=20)
                finding, verified, error = listed, [], None
                try:
                    finding = session.get_finding(listed["finding_id"])
                    if finding_fingerprint(finding) != fingerprint:
                        result.conflicts += 1
                        continue
                    refs = [{"kind": "finding", "ref": finding["finding_id"]}, *finding["evidence_refs"]]
                    seen = set()
                    for ref in refs:
                        key = (ref["kind"], ref["ref"])
                        if key in seen:
                            continue
                        seen.add(key)
                        session.resolve(ref)
                        # Arbitrary source note text is not copied into an explanatory report.
                        verified.append({"kind": ref["kind"], "ref": ref["ref"]})
                        self.heartbeat()
                except EvidenceError as exc:
                    error = exc
                finished_ms = int(self.now() * 1000)
                trace = session.trace()
                report = build_report(
                    finding, verified_refs=verified, tool_calls=trace["tool_calls"], mapping=self.mapping,
                    allow_proposed_mapping=self.allow_proposed_mapping, created_at=_timestamp(finished_ms),
                    duration_ms=trace["duration_ms"], abort_reason=error.reason if error is not None else None,
                    extra_limitations="Reference resolution checks API existence and scope; it is not an independent "
                                      "cryptographic re-audit or evidence of a completed integration scenario.")
                previous = self.store.last_attempt(finding["finding_id"], self.policy)
                attempt = 1 if previous is None else previous["attempt"] + 1
                retry_at = None
                if error is not None and error.retryable and attempt < self.max_attempts:
                    retry_at = finished_ms + min(600, self.retry_seconds * (2 ** (attempt - 1))) * 1000
                    result.retry_scheduled += 1
                metadata = {
                    "format_version": 1, "report_id": report["report_id"], "finding_id": finding["finding_id"],
                    "finding_submission_sha256": fingerprint, "generation_policy_sha256": self.policy,
                    "mapping": self.mapping.provenance, "attempt": attempt,
                    "first_observed_at": _timestamp(first_seen_ms), "generated_at": report["created_at"],
                    "observed_to_report_ms": max(0, finished_ms - first_seen_ms),
                    "core_storage_to_report_ms": None,
                    "timing_limitation": "Core does not expose finding storage time. First observation is not storage time.",
                    "reference_validation": "aborted" if report["status"] == "ABORTED" else "resolved",
                    "official_scenario_result": False, "ai_generated": False,
                }
                self.store.save(report, metadata, policy=self.policy, next_retry_ms=retry_at)
                result.generated += 1
                setattr(result, report["status"].lower(), getattr(result, report["status"].lower()) + 1)
                if error is not None:
                    result.read_errors += 1
                self.heartbeat()
                if result.generated >= self.max_reports_per_poll:
                    break
        except EvidenceError:
            # A broken discovery page is never treated as an empty successful scan.
            result.read_errors += 1
        return result


def _integer(name, default, minimum, maximum):
    value = int(os.environ.get(name, default))
    if not minimum <= value <= maximum:
        raise ValueError("Invalid audit-agent configuration bound")
    return value


def _boolean(name):
    value = os.environ.get(name, "false").strip().lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError("Invalid audit-agent boolean")
    return value in {"true", "1"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="PureVoting template audit reports (not AI), read-only HTTP inputs")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="one poll; nonzero on evidence/read errors")
    mode.add_argument("--healthcheck", action="store_true", help="liveness only; does not certify evidence or integration")
    parser.add_argument("--election-id", help="optional validated election filter")
    args = parser.parse_args(argv)
    state = Path(os.environ.get("AUDIT_STATE_DIR", str(Path.home() / ".purevoting" / "audit-agent")))
    report_dir = Path(os.environ.get("AUDIT_REPORT_DIR", str(state / "reports")))
    try:
        interval = _integer("AUDIT_POLL_SECONDS", 30, 1, 300)
        pulse = state / "heartbeat"
        if args.healthcheck:
            if not pulse.is_file():
                return 1
            # Filesystem and wall-clock readings can differ slightly in their
            # resolution. A fresh Windows heartbeat can therefore appear a few
            # milliseconds in the future. Bound that tolerance to one second;
            # stale or substantially future timestamps remain unhealthy.
            age = time.time() - pulse.stat().st_mtime
            return 0 if -1.0 <= age < max(240, 3 * interval) else 1
        if os.environ.get("AI_PROVIDER", "none").strip().lower() != "none":
            raise ValueError("This service implements the template provider only")
        key = os.environ.get("AGENT_KEY", "").strip()
        if not key or key == "<set>":
            raise ValueError("Missing agent service credential")
        mapping_path = os.environ.get("AUDIT_B1_MAPPING", "").strip()
        mapping = load_mapping(Path(mapping_path) if mapping_path else None)
        with ExitStack() as stack:
            options = dict(headers={"X-Service-Key": key}, timeout=10.0, trust_env=False, follow_redirects=False)
            core = stack.enter_context(httpx.Client(base_url=os.environ["CORE_URL"], **options))
            gateway = stack.enter_context(httpx.Client(base_url=os.environ["GATEWAY_URL"], **options))
            inputs = EvidenceClient(core, gateway)
            # URL validation is performed by EvidenceClient before these values are stored.
            binding = {"format_version": 1, "core": str(core.base_url), "gateway": str(gateway.base_url),
                       "deployment": os.environ.get("AUDIT_DEPLOYMENT_ID", "unspecified")}
            store = stack.enter_context(ReportStore(state, binding, report_dir=report_dir))
            store.recover()
            worker = AuditWorker(inputs, store, mapping,
                                 allow_proposed_mapping=_boolean("AUDIT_ALLOW_PROPOSED_MAPPING"),
                                 max_attempts=_integer("AUDIT_MAX_ATTEMPTS", 3, 1, 20),
                                 max_reports_per_poll=_integer("AUDIT_REPORTS_PER_POLL", 100, 1, 1000),
                                 retry_seconds=_integer("AUDIT_RETRY_SECONDS", 30, 1, 600), heartbeat=pulse.touch)
            while True:
                pulse.touch()
                result = worker.poll(election_id=args.election_id)
                print(json.dumps(asdict(result), sort_keys=True), flush=True)
                pulse.touch()
                if args.once:
                    return int(bool(result.read_errors or result.conflicts or result.aborted))
                time.sleep(interval)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        # No response, URL, arbitrary source text or credential enters service logs.
        print("Audit agent stopped: " + type(exc).__name__ +
              ". Check agent configuration, contracts and state/report directories.", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
