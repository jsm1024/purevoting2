"""Validate file reports; --live also resolves their references using AGENT_KEY."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from purevoting_rules.audit_evidence import (  # noqa: E402
    EvidenceClient, EvidenceError, _unique_keys, validate_report_live, validate_report_schema,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="report JSON files or directories containing report JSON files")
    parser.add_argument("--live", action="store_true", help="resolve all evidence using Core/Gateway read-only APIs")
    parser.add_argument("--core-url", default=os.environ.get("CORE_URL"))
    parser.add_argument("--gateway-url", default=os.environ.get("GATEWAY_URL"))
    args = parser.parse_args(argv)
    files = []
    for path in args.paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        else:
            files.append(path)
    files = list(dict.fromkeys(files))
    totals = {"mode": "live_references" if args.live else "schema_only", "reports": len(files),
              "valid_schema": 0, "valid_references": 0, "errors": 0,
              "evidence_checked": bool(args.live), "independent_rule_reaudit": False}
    if not files:
        totals["errors"] = 1
        totals["error_kind"] = "no_report_files"
        print(json.dumps(totals, sort_keys=True))
        return 2
    key = os.environ.get("AGENT_KEY", "")
    if args.live and (not key or not args.core_url or not args.gateway_url):
        totals["errors"] = 1
        totals["error_kind"] = "missing_live_configuration"
        print(json.dumps(totals, sort_keys=True))
        return 2
    try:
        with httpx.Client(base_url=args.core_url or "http://unused.invalid", headers={"X-Service-Key": key or "unused"},
                          timeout=10, follow_redirects=False, trust_env=False) as core, \
             httpx.Client(base_url=args.gateway_url or "http://unused.invalid", headers={"X-Service-Key": key or "unused"},
                          timeout=10, follow_redirects=False, trust_env=False) as gateway:
            client = EvidenceClient(core, gateway) if args.live else None
            for path in files:
                try:
                    if path.stat().st_size > 2 * 1024 * 1024:
                        raise ValueError("report file too large")
                    report = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_keys)
                    validate_report_schema(report)
                    totals["valid_schema"] += 1
                    if client is not None:
                        validate_report_live(report, client)
                        totals["valid_references"] += 1
                except (EvidenceError, OSError, ValueError, TypeError, UnicodeError, RecursionError):
                    totals["errors"] += 1
    except (EvidenceError, ValueError, httpx.HTTPError):
        totals["errors"] += 1
        totals["error_kind"] = "invalid_live_configuration"
    print(json.dumps(totals, sort_keys=True))
    return 0 if totals["errors"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
