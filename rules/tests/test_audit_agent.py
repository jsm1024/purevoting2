"""End-to-end template worker tests across HTTP, the durable journal and files."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from purevoting_rules.audit_agent import AuditWorker, main
from purevoting_rules.audit_evidence import EvidenceClient, finding_fingerprint, validate_report_live
from purevoting_rules.audit_report import load_mapping
from purevoting_rules.audit_store import ReportStore, ReportStoreError
from purevoting_rules.paths import reference_root


def stored_finding():
    folder = reference_root() / "contracts/examples/valid/finding"
    item = json.loads((folder / "r3_fail_pending.json").read_text(encoding="utf-8"))
    item["rule_id"] = "R5"
    item["observed"] = {"sealed_hash_mismatches": 1}
    # A reference to another stored finding exercises a real allowed tool path
    # without requiring an artificial ballot or a write to either service.
    other_id = item["finding_id"][:-1] + ("1" if item["finding_id"][-1] != "1" else "2")
    item["evidence_refs"] = [{"kind": "finding", "ref": other_id}]
    other = copy.deepcopy(item)
    other["finding_id"] = other_id
    other["evidence_refs"] = [{"kind": "finding", "ref": item["finding_id"]}]
    return item, other


class APIs:
    def __init__(self):
        self.finding, self.other = stored_finding()
        self.items = [self.finding]
        self.evidence_status = 200
        self.calls = []

    def __call__(self, request):
        self.calls.append((request.method, request.url.host, request.url.path))
        assert request.method == "GET"
        assert request.headers["X-Service-Key"] == "only-agent-test-key"
        if request.url.path == "/internal/v1/findings":
            assert request.url.params.get("has_report") == "false"
            return httpx.Response(200, json={"items": self.items, "next_cursor": None})
        if request.url.path == "/internal/v1/findings/" + self.finding["finding_id"]:
            return httpx.Response(200, json=self.finding)
        if request.url.path == "/internal/v1/findings/" + self.other["finding_id"]:
            return httpx.Response(self.evidence_status, json=self.other)
        return httpx.Response(404, json={"message": "missing"})


@pytest.fixture
def service():
    api = APIs()
    transport = httpx.MockTransport(api)
    options = {"transport": transport, "headers": {"X-Service-Key": "only-agent-test-key"},
               "trust_env": False, "follow_redirects": False}
    with httpx.Client(base_url="http://core", **options) as core, httpx.Client(base_url="http://gateway", **options) as gateway:
        yield api, EvidenceClient(core, gateway)


BINDING = {"core": "http://core/", "gateway": "http://gateway/", "deployment": "local-test"}


def reports(path):
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((path / "reports").glob("*.json"))]


def test_http_to_report_and_restart_dedup(service, tmp_path):
    api, inputs = service
    with ReportStore(tmp_path, BINDING) as store:
        worker = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True)
        result = worker.poll()
        assert (result.generated, result.completed, result.read_errors) == (1, 1, 0)
        report = reports(tmp_path)[0]
        assert report["model"]["provider"] == "none"
        assert report["hypotheses"][0]["cause_code"] == "DATA_TAMPERING"
        assert validate_report_live(report, inputs)["valid"]
        assert worker.poll().skipped == 1
        assert len(reports(tmp_path)) == 1
    before = {p.name: p.read_bytes() for p in (tmp_path / "reports").glob("*") if p.is_file()}
    with ReportStore(tmp_path, BINDING) as store:
        assert store.recover() == 1
        worker = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True)
        assert worker.poll().generated == 0
    assert before == {p.name: p.read_bytes() for p in (tmp_path / "reports").glob("*") if p.is_file()}
    metadata = json.loads(next((tmp_path / "reports/metadata").glob("*.json")).read_text(encoding="utf-8"))
    assert metadata["core_storage_to_report_ms"] is None
    assert metadata["official_scenario_result"] is False
    assert metadata["reference_validation"] == "resolved"
    assert metadata["ai_generated"] is False
    assert "not AI" in next((tmp_path / "reports").glob("*.md")).read_text(encoding="utf-8")


def test_candidate_default_escalates_and_changed_policy_can_generate_new_report(service, tmp_path):
    _, inputs = service
    with ReportStore(tmp_path, BINDING) as store:
        conservative = AuditWorker(inputs, store, load_mapping())
        assert conservative.poll().escalated == 1
        assert conservative.poll().generated == 0
        enabled = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True)
        assert enabled.poll().completed == 1
        assert enabled.poll().generated == 0
    values = reports(tmp_path)
    assert {r["status"] for r in values} == {"COMPLETED", "ESCALATED"}
    assert len({r["report_id"] for r in values}) == 2


def test_mutable_review_metadata_does_not_create_duplicate(service, tmp_path):
    api, inputs = service
    before = finding_fingerprint(api.finding)
    with ReportStore(tmp_path, BINDING) as store:
        worker = AuditWorker(inputs, store, load_mapping())
        assert worker.poll().generated == 1
        api.finding["review"]["status"] = "CONFIRMED_ISSUE"
        assert finding_fingerprint(api.finding) == before
        assert worker.poll().skipped == 1


def test_conflicting_finding_is_isolated_and_later_valid_finding_processed(service, tmp_path):
    api, inputs = service
    with ReportStore(tmp_path, BINDING) as store:
        worker = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True)
        assert worker.poll().generated == 1
        api.finding["observed"]["sealed_hash_mismatches"] = 2
        api.items.append(api.other)
        result = worker.poll()
        assert result.conflicts == 1
        assert result.generated == 1
        assert len(reports(tmp_path)) == 2


def test_transient_evidence_failure_is_recorded_then_recovers_with_bounded_retry(service, tmp_path):
    api, inputs = service
    now = [1_800_000_000]
    api.evidence_status = 503
    with ReportStore(tmp_path, BINDING) as store:
        worker = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True, now=lambda: now[0])
        result = worker.poll()
        assert (result.aborted, result.retry_scheduled, result.read_errors) == (1, 1, 1)
        assert reports(tmp_path)[0]["hypotheses"] == []
        assert worker.poll().skipped == 1
    api.evidence_status = 200
    now[0] += 30
    with ReportStore(tmp_path, BINDING) as store:
        store.recover()
        worker = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True, now=lambda: now[0])
        assert worker.poll().completed == 1
        assert worker.poll().generated == 0
    values = reports(tmp_path)
    assert len(values) == 2
    assert {r["status"] for r in values} == {"ABORTED", "COMPLETED"}
    assert len({r["report_id"] for r in values}) == 2


def test_retries_stop_at_configured_budget(service, tmp_path):
    api, inputs = service
    api.evidence_status = 503
    now = [1_800_000_000]
    with ReportStore(tmp_path, BINDING) as store:
        worker = AuditWorker(inputs, store, load_mapping(), now=lambda: now[0], max_attempts=2)
        assert worker.poll().retry_scheduled == 1
        now[0] += 30
        assert worker.poll().retry_scheduled == 0
        now[0] += 3600
        assert worker.poll().generated == 0
    assert len(reports(tmp_path)) == 2


def test_cross_election_reference_aborts_without_retry(service, tmp_path):
    api, inputs = service
    api.other["election_id"] = api.other["election_id"][:-1] + "2"
    with ReportStore(tmp_path, BINDING) as store:
        result = AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=True).poll()
        assert result.aborted == 1
        assert result.retry_scheduled == 0
    assert reports(tmp_path)[0]["status"] == "ABORTED"
    assert reports(tmp_path)[0]["hypotheses"] == []


def test_recovery_after_commit_before_export_preserves_report_id(service, tmp_path, monkeypatch):
    _, inputs = service
    with ReportStore(tmp_path, BINDING) as store:
        monkeypatch.setattr(store, "_export", lambda row: (_ for _ in ()).throw(OSError("simulated interruption")))
        with pytest.raises(OSError):
            AuditWorker(inputs, store, load_mapping()).poll()
        report_id = store.db.execute("SELECT report_id FROM attempts").fetchone()[0]
        assert reports(tmp_path) == []
    with ReportStore(tmp_path, BINDING) as store:
        assert store.recover() == 1
        assert reports(tmp_path)[0]["report_id"] == report_id
        assert AuditWorker(inputs, store, load_mapping()).poll().generated == 0


def test_missing_export_is_recreated_but_changed_export_is_not_overwritten(service, tmp_path):
    _, inputs = service
    with ReportStore(tmp_path, BINDING) as store:
        AuditWorker(inputs, store, load_mapping()).poll()
        path = next((tmp_path / "reports").glob("*.json"))
        original = path.read_bytes()
        path.unlink()
        store.recover()
        assert path.read_bytes() == original
        path.write_bytes(b"altered")
        with pytest.raises(ReportStoreError):
            store.recover()
        assert path.read_bytes() == b"altered"


def test_store_binds_deployment_and_allows_only_one_writer(tmp_path):
    with ReportStore(tmp_path, BINDING):
        with pytest.raises(ReportStoreError):
            ReportStore(tmp_path, BINDING)
    with pytest.raises(ReportStoreError, match="different service deployment"):
        ReportStore(tmp_path, {**BINDING, "deployment": "other"})


@pytest.mark.parametrize("changed_column", ["metadata", "status", "next_retry_ms", "policy"])
def test_journal_recovery_detects_changed_provenance_or_retry_state(service, tmp_path, changed_column):
    api, inputs = service
    api.evidence_status = 503
    with ReportStore(tmp_path, BINDING) as store:
        worker = AuditWorker(inputs, store, load_mapping())
        assert worker.poll().aborted == 1
        row = store.db.execute("SELECT * FROM attempts").fetchone()
        if changed_column == "metadata":
            value = json.loads(row["metadata"])
            value["official_scenario_result"] = True
            new_value = json.dumps(value)
        elif changed_column == "status":
            new_value = "COMPLETED"
        elif changed_column == "next_retry_ms":
            new_value = None
        else:
            new_value = "altered-policy"
        with store.db:
            store.db.execute(f"UPDATE attempts SET {changed_column}=?", (new_value,))
        metadata_path = next((tmp_path / "reports/metadata").glob("*.json"))
        metadata_path.unlink()
        with pytest.raises(ReportStoreError, match="digest mismatch"):
            store.recover()
        assert not metadata_path.exists()


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None])
def test_worker_candidate_opt_in_requires_boolean(service, tmp_path, value):
    _, inputs = service
    with ReportStore(tmp_path, BINDING) as store:
        with pytest.raises(ValueError):
            AuditWorker(inputs, store, load_mapping(), allow_proposed_mapping=value)


def test_cli_healthcheck_needs_no_key_and_does_not_mean_integration_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_KEY", raising=False)
    assert main(["--healthcheck"]) == 1
    (tmp_path / "heartbeat").touch()
    assert main(["--healthcheck"]) == 0


def test_cli_rejects_non_template_provider_without_network(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("AUDIT_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AI_PROVIDER", "remote-provider")
    monkeypatch.setenv("AGENT_KEY", "secret-not-in-logs")
    assert main(["--once"]) == 2
    assert "secret-not-in-logs" not in capsys.readouterr().out


@pytest.mark.parametrize("age,expected", [
    (-0.020, 0),  # Different filesystem/wall-clock resolution on a fresh write.
    (-0.900, 0),
    (-1.100, 1),  # The future-timestamp tolerance is bounded.
    (240.0, 1),   # Preserve the existing stale-heartbeat cutoff.
    (float("nan"), 1),
    (float("inf"), 1),
])
def test_cli_healthcheck_bounds_clock_skew_and_stale_timestamps(tmp_path, monkeypatch, age, expected):
    monkeypatch.setenv("AUDIT_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_POLL_SECONDS", "30")
    monkeypatch.delenv("AGENT_KEY", raising=False)
    pulse = tmp_path / "heartbeat"
    pulse.touch()
    stamp = pulse.stat().st_mtime
    monkeypatch.setattr("purevoting_rules.audit_agent.time.time", lambda: stamp + age)
    assert main(["--healthcheck"]) == expected


def test_cli_healthcheck_rejects_non_file_heartbeat(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_STATE_DIR", str(tmp_path))
    (tmp_path / "heartbeat").mkdir()
    assert main(["--healthcheck"]) == 1
