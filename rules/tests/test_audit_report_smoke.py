"""Actual loopback HTTP and separate CLI processes; no external services."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "rules/devtools/audit_report_smoke.py"


def invoke(output):
    env = dict(os.environ)
    # The helper must ignore every inherited deployment/provider setting.
    env.update({
        "CORE_URL": "http://must-not-contact.invalid",
        "GATEWAY_URL": "http://must-not-contact.invalid",
        "AGENT_KEY": "inherited-key-must-not-be-used",
        "AI_PROVIDER": "external-provider-must-not-be-used",
        "AUDIT_B1_MAPPING": str(output / "nonexistent-mapping.json"),
        "AUDIT_REPORT_DIR": str(output / "must-not-use-inherited-directory"),
        "AUDIT_ALLOW_PROPOSED_MAPPING": "false",
        "PYTHONUTF8": "1",
    })
    return subprocess.run(
        [sys.executable, str(HELPER), "--output-dir", str(output)], cwd=REPO, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=False,
    )


def test_real_cli_processes_over_synthetic_http_and_restart(tmp_path):
    output = tmp_path / "synthetic_http"
    result = invoke(output)
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["passed"] is True
    assert summary["smoke"] == "synthetic developer HTTP smoke"
    for flag in ("real_core", "real_gateway", "real_chain", "official_scenario",
                 "official_T01_run", "E1_finalization_verified", "ai_generated"):
        assert summary[flag] is False
    assert summary["provider"] == "none"
    assert summary["report_statuses"] == {"COMPLETED": 1, "ESCALATED": 1}
    assert summary["live_reference_validation"]["valid_references"] == 2
    assert summary["live_reference_validation"]["evidence_checked"] is True
    assert summary["live_reference_validation"]["independent_rule_reaudit"] is False
    assert summary["restart"]["generated"] == 0
    assert summary["restart"]["skipped"] == 2
    assert summary["restart_same_report_ids"] is True
    assert summary["restart_same_report_bytes"] is True
    assert summary["http"]["get_requests"] >= 6
    assert summary["http"]["write_requests"] == summary["http"]["unexpected_requests"] == 0
    assert summary == json.loads((output / "summary.json").read_text(encoding="utf-8"))
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in (output / "reports").glob("*.json")]
    assert len(reports) == 2
    assert {report["status"] for report in reports} == {"COMPLETED", "ESCALATED"}
    assert all(report["model"]["provider"] == "none" for report in reports)
    assert len(list((output / "reports/metadata").glob("*.json"))) == 2
    assert all("not AI" in path.read_text(encoding="utf-8") for path in (output / "reports").glob("*.md"))
    assert not (output / "must-not-use-inherited-directory").exists()
    assert "inherited-key-must-not-be-used" not in result.stdout + result.stderr
    assert not result.stderr


def test_existing_output_directory_is_never_reused(tmp_path):
    output = tmp_path / "already_exists"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep existing files", encoding="utf-8")
    result = invoke(output)
    assert result.returncode == 2
    summary = json.loads(result.stdout)
    assert summary["passed"] is False
    assert summary["error_kind"] == "output_directory_already_exists"
    assert sentinel.read_text(encoding="utf-8") == "keep existing files"
    assert list(output.iterdir()) == [sentinel]
    assert not result.stderr
