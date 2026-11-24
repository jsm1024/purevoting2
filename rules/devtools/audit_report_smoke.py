"""Exercise the real template-agent CLI against an isolated synthetic HTTP API.

This developer check proves report plumbing only. It does not contact Core,
Gateway or PureChain, exercise Docker, establish official T01/E1 evidence, or
measure root-cause accuracy. The proposed B1 mapping is enabled only for this
explicit synthetic run. No real credentials or inherited service URLs are used.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


_SYNTHETIC_KEY = "synthetic-audit-agent-key-not-a-real-secret"
_FAIL_ID = "fnd_" + "1" * 26
_UNKNOWN_ID = "fnd_" + "2" * 26
_POLL_FIELDS = (
    "discovered", "skipped", "generated", "completed", "escalated", "aborted",
    "read_errors", "conflicts", "retry_scheduled",
)


class SmokeFailure(RuntimeError):
    """Only fixed, non-sensitive error categories cross the CLI boundary."""


def _labels():
    return {
        "smoke": "synthetic developer HTTP smoke",
        "real_core": False,
        "real_gateway": False,
        "real_chain": False,
        "official_scenario": False,
        "official_T01_run": False,
        "E1_finalization_verified": False,
        "ai_generated": False,
        "provider": "none",
        "mapping": "proposed B1 mapping, synthetic opt-in only",
        "scope": "Report generation, HTTP reference existence, and restart deduplication; not AI.",
    }


def _fixtures(repo):
    examples = repo / "contracts/examples/valid"
    finding = json.loads((examples / "finding/r3_fail_pending.json").read_text(encoding="utf-8"))
    event = json.loads((examples / "ledger-events/checkpoint_committed.json").read_text(encoding="utf-8"))
    finding.update({
        "finding_id": _FAIL_ID,
        "rule_id": "R5",
        "observed": {"sealed_hash_mismatches": 1},
        "expected": "Synthetic developer fixture: no sealed hash discrepancies.",
        "summary": "Synthetic developer report-plumbing fixture; no real election was audited.",
        "evidence_refs": [{"kind": "ledger_event", "ref": event["event_id"]}],
    })
    unknown = copy.deepcopy(finding)
    unknown.update({
        "finding_id": _UNKNOWN_ID,
        "result": "INCONCLUSIVE",
        "inconclusive_reason": "OTHER",
        "severity": "MEDIUM",
        "observed": {"available_inputs": 0},
        "expected": "Synthetic developer fixture: sufficient inputs to classify a cause.",
        "summary": "Synthetic unknown-cause fixture requiring human investigation.",
    })
    return [finding, unknown], event


@contextmanager
def _synthetic_api(findings, event):
    counts = {"get_requests": 0, "write_requests": 0, "unexpected_requests": 0}
    lock = threading.Lock()
    by_id = {item["finding_id"]: item for item in findings}

    class Handler(BaseHTTPRequestHandler):
        # Suppress the standard log: request targets and headers never enter output.
        def log_message(self, *_args):
            pass

        def _send(self, status, value):
            body = json.dumps(value, ensure_ascii=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _unexpected(self, status=404):
            with lock:
                counts["unexpected_requests"] += 1
            self._send(status, {"error": "unsupported synthetic request"})

        def do_GET(self):
            with lock:
                counts["get_requests"] += 1
            if self.headers.get("X-Service-Key") != _SYNTHETIC_KEY:
                self._unexpected(401)
                return
            target = urlsplit(self.path)
            if target.scheme or target.netloc or target.fragment:
                self._unexpected(400)
                return
            params = parse_qs(target.query, keep_blank_values=True)
            if target.path == "/internal/v1/findings":
                if (set(params) != {"result", "has_report", "limit"}
                        or sorted(params.get("result", [])) != ["FAIL", "INCONCLUSIVE"]
                        or params.get("has_report") != ["false"]
                        or params.get("limit") != ["100"]):
                    self._unexpected(400)
                    return
                self._send(200, {"items": findings, "next_cursor": None})
            elif params:
                self._unexpected(400)
            elif target.path.startswith("/internal/v1/findings/"):
                finding = by_id.get(target.path.removeprefix("/internal/v1/findings/"))
                if finding is None:
                    self._unexpected()
                else:
                    self._send(200, finding)
            elif target.path == "/v1/events/" + event["event_id"]:
                self._send(200, event)
            else:
                self._unexpected()

        def _write(self):
            with lock:
                counts["write_requests"] += 1
            self._send(405, {"error": "synthetic API is read-only"})

        do_POST = do_PUT = do_PATCH = do_DELETE = _write

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, _request, _address):
            # Server tracebacks could include arbitrary request context.
            with lock:
                counts["unexpected_requests"] += 1

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_address[1]), counts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _child_environment(repo, output, base_url):
    # Preserve only OS process essentials. Inherited Core/Gateway URLs, service
    # keys, proxies, Python startup hooks and audit configuration are excluded.
    names = (
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
        "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "LANG", "LC_ALL",
    )
    env = {name: os.environ[name] for name in names if name in os.environ}
    env.update({
        "PYTHONPATH": str(repo / "rules"),
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PUREVOTING_REFERENCE_ROOT": str(repo),
        "CORE_URL": base_url,
        "GATEWAY_URL": base_url,
        "AGENT_KEY": _SYNTHETIC_KEY,
        "AI_PROVIDER": "none",
        "AUDIT_ALLOW_PROPOSED_MAPPING": "true",
        "AUDIT_B1_MAPPING": str(repo / "rules/config/b1-cause-map.pr10.json"),
        "AUDIT_STATE_DIR": str(output / "state"),
        "AUDIT_REPORT_DIR": str(output / "reports"),
        "AUDIT_DEPLOYMENT_ID": "synthetic-audit-report-http-smoke",
    })
    return env


def _run_json(command, *, repo, env, stage):
    try:
        result = subprocess.run(
            command, cwd=repo, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SmokeFailure(stage + "_execution_failed") from None
    if result.returncode != 0:
        raise SmokeFailure(stage + "_failed")
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise SmokeFailure(stage + "_invalid_summary") from None


def _poll_counts(value):
    if any(type(value.get(key)) is not int or value[key] < 0 for key in _POLL_FIELDS):
        raise SmokeFailure("invalid_poll_counts")
    return {key: value[key] for key in _POLL_FIELDS}


def _report_snapshot(report_dir):
    return {path.relative_to(report_dir).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(report_dir.rglob("*")) if path.is_file()}


def _run_in_directory(repo, output):
    findings, event = _fixtures(repo)
    report_dir = output / "reports"
    with _synthetic_api(findings, event) as (base_url, counts):
        env = _child_environment(repo, output, base_url)
        agent_command = [sys.executable, "-m", "purevoting_rules.audit_agent", "--once"]
        first = _poll_counts(_run_json(agent_command, repo=repo, env=env, stage="first_agent_run"))
        if first != {
            "discovered": 2, "skipped": 0, "generated": 2, "completed": 1,
            "escalated": 1, "aborted": 0, "read_errors": 0, "conflicts": 0, "retry_scheduled": 0,
        }:
            raise SmokeFailure("first_poll_expectation_failed")
        reports = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(report_dir.glob("*.json"))]
        by_finding = {report["finding_id"]: report for report in reports}
        if (len(reports) != 2 or set(by_finding) != {_FAIL_ID, _UNKNOWN_ID}
                or by_finding[_FAIL_ID]["status"] != "COMPLETED"
                or by_finding[_FAIL_ID]["hypotheses"][0]["cause_code"] != "DATA_TAMPERING"
                or by_finding[_UNKNOWN_ID]["status"] != "ESCALATED"
                or by_finding[_UNKNOWN_ID]["hypotheses"]
                or any(report["model"]["provider"] != "none" or report["model"]["name"] != "template"
                       for report in reports)):
            raise SmokeFailure("report_expectation_failed")
        before_ids = sorted(report["report_id"] for report in reports)
        before_bytes = _report_snapshot(report_dir)
        if len(before_bytes) != 6:
            raise SmokeFailure("report_exports_missing")

        validated = _run_json(
            [sys.executable, str(repo / "rules/devtools/validate_audit_reports.py"), str(report_dir), "--live"],
            repo=repo, env=env, stage="live_reference_validation",
        )
        expected_validation = {
            "mode": "live_references", "reports": 2, "valid_schema": 2, "valid_references": 2,
            "errors": 0, "evidence_checked": True, "independent_rule_reaudit": False,
        }
        if validated != expected_validation:
            raise SmokeFailure("reference_validation_expectation_failed")

        restart = _poll_counts(_run_json(agent_command, repo=repo, env=env, stage="restarted_agent_run"))
        after_ids = sorted(json.loads(path.read_text(encoding="utf-8"))["report_id"]
                           for path in report_dir.glob("*.json"))
        same_bytes = before_bytes == _report_snapshot(report_dir)
        same_ids = before_ids == after_ids
        if (restart != {key: (2 if key in {"discovered", "skipped"} else 0) for key in _POLL_FIELDS}
                or not same_bytes or not same_ids):
            raise SmokeFailure("restart_deduplication_failed")
        if counts["write_requests"] or counts["unexpected_requests"] or counts["get_requests"] < 6:
            raise SmokeFailure("unexpected_http_activity")
        summary = {
            **_labels(), "passed": True,
            "first_poll": first,
            "report_statuses": {"COMPLETED": 1, "ESCALATED": 1},
            "live_reference_validation": expected_validation,
            "restart": restart,
            "restart_same_report_ids": same_ids,
            "restart_same_report_bytes": same_bytes,
            "http": dict(counts),
        }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def run_smoke(output_dir: Path | None = None):
    """Run only against a private loopback server; retain files on explicit opt-in."""
    repo = Path(__file__).resolve().parents[2]
    if output_dir is not None:
        output = Path(output_dir).expanduser().absolute()
        try:
            output.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            raise SmokeFailure("output_directory_already_exists") from None
        return _run_in_directory(repo, output)
    with tempfile.TemporaryDirectory(prefix="purevoting-synthetic-audit-http-") as temporary:
        return _run_in_directory(repo, Path(temporary))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="retain synthetic reports in this new, non-existing directory")
    args = parser.parse_args(argv)
    try:
        summary = run_smoke(args.output_dir)
    except SmokeFailure as exc:
        summary = {**_labels(), "passed": False, "error_kind": str(exc)}
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        summary = {**_labels(), "passed": False, "error_kind": "synthetic_smoke_failed"}
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
