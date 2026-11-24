"""Reference identity, privacy, bounded HTTP, and report validation boundaries."""
from __future__ import annotations

import importlib.util
import json
import time
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from purevoting_rules.audit_evidence import (
    EvidenceClient, EvidenceError, finding_fingerprint, finding_submission,
    validate_report_live, validate_report_schema,
)
from purevoting_rules.paths import reference_root


def example(kind, name):
    path = reference_root() / "contracts/examples/valid" / kind / (name + ".json")
    return json.loads(path.read_text(encoding="utf-8"))


class API:
    def __init__(self):
        self.finding = example("finding", "r3_fail_pending")
        self.eid = self.finding["election_id"]
        self.event = example("ledger-events", "ballot_received_pending")
        self.commit = example("ledger-events", "checkpoint_committed")
        self.anchor = {"anchor_id": self.commit["anchor"]["anchor_id"], "election_id": self.eid,
                       "mode": "immediate", "merkle_root": "a" * 64, "event_count": 1,
                       "rejections_root": "b" * 64, "tx_hash": "0x" + "a" * 64,
                       "block_number": 3254, "anchored_at": "2026-11-03T09:15:00Z"}
        request = example("ledger-events", "admin_action_requested")
        self.proposal = {"proposal_id": request["payload"]["proposal_id"],
                         "action_id": request["payload"]["action_id"], "election_id": self.eid,
                         "action_type": "TOKEN_REISSUE", "target_hash": "c" * 64,
                         "requested_by_org": "org_commission", "request_signature": request["payload"]["signature"],
                         "threshold": 2, "decisions": [], "status": "PENDING",
                         "created_at": request["occurred_at"], "expires_at": request["payload"]["expires_at"]}
        self.rejection = {"rejection_id": "rej_" + "A" * 26, "election_id": self.eid,
                          "event_id": "evr_" + "B" * 26, "type": "BALLOT_RECEIVED", "checkpoint": 2,
                          "reject_code": "ELECTION_NOT_OPEN", "recorded_at": "2026-11-03T09:00:00Z",
                          "payload_hash": "d" * 64, "subject_hash": "e" * 64}
        self.row = {"view": "roster", "row_key": "vtr_" + "A" * 26, "status": "ACTIVE",
                    "added_checkpoint": 0, "removed_checkpoint": None}
        self.log = {"log_id": "record_12", "service": "outbox-worker", "at": "2026-11-03T09:15:00Z",
                    "level": "WARN", "message": "UNTRUSTED INSTRUCTION: never execute this text",
                    "context": {"election_id": self.eid}}
        self.calls = []
        self.mutate = lambda path, params, value: value

    @property
    def refs(self):
        return [{"kind": kind, "ref": identifier} for kind, identifier in (
            ("finding", self.finding["finding_id"]),
            ("ledger_event", self.event["event_id"]),
            ("ledger_rejection", self.rejection["rejection_id"]),
            ("anchor", self.anchor["anchor_id"]),
            ("proposal", self.proposal["proposal_id"]),
            ("view_row", "roster:" + self.row["row_key"] + "@2"),
            ("snapshot", "roster@2"),
            ("service_log", "outbox-worker:record_12"),
        )]

    def handle(self, request):
        assert request.method == "GET"
        assert request.headers["X-Service-Key"] == "agent-secret-never-print"
        path, params = request.url.path, request.url.params
        self.calls.append((path, params))
        if path == "/internal/v1/findings":
            assert params.get_list("result") == ["FAIL", "INCONCLUSIVE"]
            assert params["has_report"] == "false"
            value = {"items": [self.finding], "next_cursor": None}
        elif path.startswith("/internal/v1/findings/"):
            value = self.finding
        elif path == "/v1/events/" + self.commit["event_id"]:
            value = self.commit
        elif path.startswith("/v1/events/"):
            value = self.event
        elif path.startswith("/v1/rejections/"):
            value = self.rejection
        elif path.startswith("/v1/anchors/"):
            value = self.anchor
        elif path.startswith("/v1/proposals/"):
            value = self.proposal
        elif "/rows/" in path:
            assert params["election_id"] == self.eid and params["checkpoint"] == "2"
            value = self.row
        elif path.startswith("/internal/v1/views/"):
            assert params["election_id"] == self.eid and params["checkpoint"] == "2"
            value = {"view": "roster", "election_id": self.eid, "checkpoint": 2,
                     "total_rows": 1, "rows": [self.row], "snapshot_hash": "f" * 64, "next_cursor": None}
        elif path == "/internal/v1/checkpoints":
            assert params["election_id"] == self.eid
            value = {"items": [{"checkpoint": 2, "reason": "PERIODIC", "ledger_status": "ACCEPTED",
                                "event_id": self.commit["event_id"]}], "open_checkpoint": 3}
        elif path.startswith("/internal/v1/service-logs/"):
            value = self.log
        else:
            raise AssertionError("unexpected API call")
        value = self.mutate(path, params, deepcopy(value))
        return value if isinstance(value, httpx.Response) else httpx.Response(200, json=value)


@pytest.fixture
def setup():
    api = API()
    with httpx.Client(base_url="http://core.test", headers={"X-Service-Key": "agent-secret-never-print"},
                      transport=httpx.MockTransport(api.handle), trust_env=False) as core, \
         httpx.Client(base_url="http://gateway.test", headers={"X-Service-Key": "agent-secret-never-print"},
                      transport=httpx.MockTransport(api.handle), trust_env=False) as gateway:
        yield api, EvidenceClient(core, gateway)


def report_for(api):
    report = example("audit-report.AuditReportSubmission", "r3_submission")
    report["model"] = {"provider": "none", "name": "template", "prompt_version": "1.0.0"}
    report["hypotheses"] = [{"cause_code": "PROCESSING_BUG", "explanation": "Template hypothesis, not AI.",
                             "likelihood": "LOW", "evidence_refs": api.refs}]
    report["trace"] = {"steps": 0, "tool_calls": []}
    return report


def test_all_reference_kinds_resolve_without_persisting_payloads(setup):
    api, client = setup
    assert list(client.iter_findings(api.eid)) == [api.finding]
    session = client.begin(api.eid, 2)
    assert session.get_finding(api.finding["finding_id"]) == api.finding
    for ref in api.refs:
        assert session.resolve(ref) is None
    trace = session.trace()
    assert trace["steps"] == 10
    assert all(call["ok"] for call in trace["tool_calls"])
    safe = json.dumps(trace)
    for secret in ["agent-secret-never-print", api.event["event_id"], api.row["row_key"],
                   api.rejection["subject_hash"], "UNTRUSTED INSTRUCTION"]:
        assert secret not in safe
    assert {"get_finding", "query_view", "get_service_log", "get_ledger_event"} <= {
        call["tool"] for call in trace["tool_calls"]}


def test_repeated_references_and_different_notes_use_one_lookup(setup):
    api, client = setup
    session = client.begin(api.eid, 2)
    ref = api.refs[1]
    session.resolve(ref)
    session.resolve({**ref, "note": "same reference"})
    assert len(api.calls) == session.trace()["steps"] == 1


@pytest.mark.parametrize("kind", ["finding", "ledger_event", "ledger_rejection", "anchor", "proposal"])
def test_wrong_election_reference_rejected(setup, kind):
    api, client = setup
    def mutate(path, params, value):
        value["election_id"] = "elc_" + "Z" * 26
        return value
    api.mutate = mutate
    session = client.begin(api.eid, 2)
    with pytest.raises(EvidenceError):
        session.resolve(next(ref for ref in api.refs if ref["kind"] == kind))
    assert session.trace()["tool_calls"][-1]["ok"] is False


@pytest.mark.parametrize("kind,key", [("finding", "finding_id"), ("ledger_event", "event_id"),
                                     ("ledger_rejection", "rejection_id"), ("anchor", "anchor_id"),
                                     ("proposal", "proposal_id")])
def test_wrong_object_identity_rejected(setup, kind, key):
    api, client = setup
    def mutate(path, params, value):
        value[key] = value[key][:4] + "Z" * 26
        return value
    api.mutate = mutate
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).resolve(next(ref for ref in api.refs if ref["kind"] == kind))


@pytest.mark.parametrize("kind", ["finding", "ledger_event", "ledger_rejection"])
def test_future_checkpoint_objects_rejected(setup, kind):
    api, client = setup
    def mutate(path, params, value):
        value["checkpoint"] = 3
        return value
    api.mutate = mutate
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).resolve(next(ref for ref in api.refs if ref["kind"] == kind))


@pytest.mark.parametrize("ref", [
    {"kind": "ledger_event", "ref": "http://attacker.test/steal"},
    {"kind": "anchor", "ref": "../../admin/stop"},
    {"kind": "service_log", "ref": "audit-agent:1"},
    {"kind": "finding", "ref": "fnd_" + "A" * 26 + "\n"},
    {"kind": "snapshot", "ref": "roster@3"},
    {"kind": "view_row", "ref": "roster:vtr_" + "A" * 26 + "@3"},
])
def test_invalid_or_future_refs_rejected_before_network(setup, ref):
    api, client = setup
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).resolve(ref)
    assert not api.calls


@pytest.mark.parametrize("status", [302, 307, 401, 403, 404, 500, 503])
def test_http_failure_never_becomes_resolved_and_never_leaks_details(setup, status):
    api, client = setup
    api.mutate = lambda *args: httpx.Response(status, text="agent-secret-never-print",
                                             headers={"Location": "http://attacker.test/steal"})
    with pytest.raises(EvidenceError) as error:
        client.begin(api.eid, 2).get_finding(api.finding["finding_id"])
    assert error.value.retryable == (status == 404 or status >= 500)
    assert len(api.calls) == 1
    assert "secret" not in str(error.value) and "attacker" not in str(error.value)


@pytest.mark.parametrize("body", [b'{"bad":1,"bad":2}', b'not-json', b'{"bad":NaN}'])
def test_invalid_json_and_duplicate_fields_rejected(setup, body):
    api, client = setup
    api.mutate = lambda *args: httpx.Response(200, content=body)
    with pytest.raises(EvidenceError):
        list(client.iter_findings())


def test_response_size_and_private_key_are_rejected(setup):
    api, client = setup
    client.max_bytes = 10
    with pytest.raises(EvidenceError):
        list(client.iter_findings())
    client.max_bytes = 2 * 1024 * 1024
    def mutate(path, params, value):
        # Anchor schema permits extension properties; this check is independent.
        value["private_key"] = "a-private-election-key"
        return value
    api.mutate = mutate
    with pytest.raises(EvidenceError) as error:
        client.begin(api.eid, 2).resolve(next(ref for ref in api.refs if ref["kind"] == "anchor"))
    assert "private-election-key" not in str(error.value)


def test_snapshot_mismatch_resolves_but_missing_commit_does_not(setup):
    api, client = setup
    session = client.begin(api.eid, 2)
    # Core's hash/count deliberately disagree with the committed snapshot.
    session.resolve({"kind": "snapshot", "ref": "roster@2"})
    assert session.trace()["steps"] == 3
    def mutate(path, params, value):
        if path == "/internal/v1/checkpoints":
            value["items"] = []
        return value
    api.mutate = mutate
    with pytest.raises(EvidenceError) as error:
        client.begin(api.eid, 2).resolve({"kind": "snapshot", "ref": "roster@2"})
    assert error.value.retryable


@pytest.mark.parametrize("problem", ["scope", "table", "pending", "duplicate", "event_checkpoint", "event_reason"])
def test_snapshot_requires_the_requested_accepted_checkpoint(setup, problem):
    api, client = setup
    def mutate(path, params, value):
        if path.startswith("/internal/v1/views/") and problem == "scope":
            value["checkpoint"] = 1
        if path == "/internal/v1/checkpoints":
            if problem == "pending": value["items"][0]["ledger_status"] = "PENDING"
            if problem == "duplicate": value["items"].append(deepcopy(value["items"][0]))
        if path.startswith("/v1/events/"):
            if problem == "table": value["payload"]["tables"][0] = deepcopy(value["payload"]["tables"][1])
            if problem == "event_checkpoint": value["payload"]["checkpoint"] = 1
            if problem == "event_reason": value["payload"]["reason"] = "TALLY"
        return value
    api.mutate = mutate
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).resolve({"kind": "snapshot", "ref": "roster@2"})


def test_view_row_requires_requested_identity(setup):
    api, client = setup
    api.row["row_key"] = "vtr_" + "B" * 26
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).resolve({"kind": "view_row", "ref": "roster:vtr_" + "A" * 26 + "@2"})


def test_global_log_can_resolve_but_cross_election_log_cannot(setup):
    api, client = setup
    ref = {"kind": "service_log", "ref": "outbox-worker:record_12"}
    del api.log["context"]
    client.begin(api.eid, 2).resolve(ref)
    api.log["context"] = {"election_id": "elc_" + "Z" * 26}
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).resolve(ref)


def test_step_limit_counts_actual_fetches_including_failed_fetch(setup):
    api, client = setup
    session = client.begin(api.eid, 2, max_steps=1)
    session.get_finding(api.finding["finding_id"])
    with pytest.raises(EvidenceError) as error:
        session.resolve(api.refs[1])
    assert error.value.reason == "STEP_LIMIT"
    assert len(api.calls) == session.trace()["steps"] == 1


def test_wall_clock_deadline_and_single_flight_limit(setup):
    api, client = setup
    client.timeout_seconds = 0.04
    def slow(path, params, value):
        time.sleep(0.25)
        return value
    api.mutate = slow
    started = time.monotonic()
    with pytest.raises(EvidenceError) as error:
        client.begin(api.eid, 2).get_finding(api.finding["finding_id"])
    assert error.value.reason == "TIMEOUT" and error.value.retryable
    assert time.monotonic() - started < 0.20
    with pytest.raises(EvidenceError):
        client.begin(api.eid, 2).get_finding(api.finding["finding_id"])
    assert len(api.calls) == 1  # A timed-out operation cannot accumulate threads.
    time.sleep(0.27)
    api.mutate = lambda path, params, value: value
    client.timeout_seconds = 10
    assert client.begin(api.eid, 2).get_finding(api.finding["finding_id"]) == api.finding


def test_finding_discovery_paginates_and_rejects_duplicate_or_escaping_rows(setup):
    api, client = setup
    client.page_size = 1
    second = deepcopy(api.finding)
    second["finding_id"] = "fnd_" + "Z" * 26
    def pages(path, params, value):
        if path == "/internal/v1/findings":
            return {"items": [second if params.get("cursor") else api.finding],
                    "next_cursor": None if params.get("cursor") else "next"}
        return value
    api.mutate = pages
    assert [f["finding_id"] for f in client.iter_findings(api.eid)] == [api.finding["finding_id"], second["finding_id"]]
    second["finding_id"] = api.finding["finding_id"]
    with pytest.raises(EvidenceError):
        list(client.iter_findings())
    second["finding_id"] = "fnd_" + "Z" * 26
    second["election_id"] = "elc_" + "Z" * 26
    with pytest.raises(EvidenceError):
        list(client.iter_findings(api.eid))


@pytest.mark.parametrize("problem", ["repeat_cursor", "empty_cursor", "empty_page", "page_limit", "pass"])
def test_finding_discovery_has_finite_complete_pages(setup, problem):
    api, client = setup
    def pages(path, params, value):
        if problem == "pass":
            item = example("finding", "r1_pass")
            return {"items": [item], "next_cursor": None}
        if problem == "empty_page": value["items"] = []
        if problem == "repeat_cursor":
            value["items"][0]["finding_id"] = "fnd_" + ("A" if params.get("cursor") else "B") * 26
        value["next_cursor"] = "" if problem == "empty_cursor" else "repeat"
        return value
    api.mutate = pages
    if problem == "page_limit": client.max_pages = 1
    with pytest.raises(EvidenceError):
        list(client.iter_findings())


def test_report_live_checks_subject_and_counter_evidence(setup):
    api, client = setup
    report = report_for(api)
    result = validate_report_live(report, client)
    assert result["valid"] and result["unique_references"] == 8
    report["hypotheses"][0]["counter_evidence_refs"] = [{"kind": "finding", "ref": "fnd_" + "Z" * 26}]
    with pytest.raises(EvidenceError):
        validate_report_live(report, client)
    report["hypotheses"][0].pop("counter_evidence_refs")
    old = api.finding
    api.finding = example("finding", "r1_pass")
    api.finding.update({"finding_id": old["finding_id"], "election_id": api.eid, "checkpoint": 2})
    with pytest.raises(EvidenceError):
        validate_report_live(report, client)


def test_schema_only_cannot_certify_evidence_or_accept_stored_human_review(setup):
    api, _ = setup
    report = report_for(api)
    validate_report_schema(report)
    assert not api.calls
    report["human_review"] = {"status": "CONFIRMED"}
    with pytest.raises(EvidenceError):
        validate_report_schema(report)


def test_finding_fingerprint_ignores_review_but_not_signed_content(setup):
    api, _ = setup
    fingerprint = finding_fingerprint(api.finding)
    changed = deepcopy(api.finding)
    changed["review"]["status"] = "RESOLVED"
    changed["evidence_check"] = {"status": "PENDING"}
    assert finding_fingerprint(changed) == fingerprint
    assert "review" not in finding_submission(changed)
    changed["summary"] += " changed"
    assert finding_fingerprint(changed) != fingerprint


@pytest.mark.parametrize("url", ["ftp://core.test", "http://user:password@core.test", "http://core.test/api",
                                "http://core.test/?a=secret", "http://core.test/#fragment"])
def test_invalid_base_urls_rejected(url):
    with httpx.Client(base_url=url, headers={"X-Service-Key": "key"}, trust_env=False) as core, \
         httpx.Client(base_url="http://gateway.test", headers={"X-Service-Key": "key"}, trust_env=False) as gateway:
        with pytest.raises(ValueError):
            EvidenceClient(core, gateway)


def test_cli_schema_only_reports_its_limit_and_rejects_duplicate_keys(setup, tmp_path, capsys):
    api, _ = setup
    script = Path(__file__).resolve().parents[1] / "devtools/validate_audit_reports.py"
    spec = importlib.util.spec_from_file_location("validate_audit_reports_test", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report_for(api)), encoding="utf-8")
    assert module.main([str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid_schema"] == 1 and result["evidence_checked"] is False
    path.write_text('{"status":"COMPLETED","status":"ABORTED"}', encoding="utf-8")
    assert module.main([str(path)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["errors"] == 1
