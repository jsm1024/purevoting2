"""Bounded, read-only evidence resolution for file-based audit reports.

Resolution establishes that a reference exists with the requested identity and
scope. It does not independently re-run a rule, authenticate a historical chain
state, or establish that a finding's suggested cause is true. Raw responses are
kept only in the short-lived investigation; trace entries omit identifiers and
payloads. In particular, a snapshot mismatch is evidence, not a lookup failure.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import queue
import threading
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

import httpx
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry
from referencing.jsonschema import DRAFT202012

from .hashing import canonical
from .paths import reference_root

_BASE = "https://purevoting2.local/contracts/"
_RESPONSES = {
    "findings": ("core-api.openapi.yaml", "/internal/v1/findings"),
    "finding": ("core-api.openapi.yaml", "/internal/v1/findings/{finding_id}"),
    "checkpoints": ("core-api.openapi.yaml", "/internal/v1/checkpoints"),
    "view": ("core-api.openapi.yaml", "/internal/v1/views/{view}"),
    "row": ("core-api.openapi.yaml", "/internal/v1/views/{view}/rows/{row_key}"),
    "log": ("core-api.openapi.yaml", "/internal/v1/service-logs/{service}/{log_id}"),
    "event": ("ledger-gateway.openapi.yaml", "/v1/events/{event_id}"),
    "rejection": ("ledger-gateway.openapi.yaml", "/v1/rejections/{rejection_id}"),
    "anchor": ("ledger-gateway.openapi.yaml", "/v1/anchors/{anchor_id}"),
    "proposal": ("ledger-gateway.openapi.yaml", "/v1/proposals/{proposal_id}"),
}


class EvidenceError(Exception):
    """Sanitized failure; never includes a URL, response body, reference or key."""

    def __init__(self, reason: str = "TOOL_ERROR", kind: str = "invalid", *, retryable: bool = False):
        if reason not in {"TOOL_ERROR", "TIMEOUT", "STEP_LIMIT"}:
            raise ValueError("invalid evidence error reason")
        if kind not in {"invalid", "unavailable", "not_found", "limit"}:
            raise ValueError("invalid evidence error kind")
        self.reason, self.kind, self.retryable = reason, kind, retryable
        super().__init__(f"evidence {kind}: {reason}")


def _invalid() -> EvidenceError:
    return EvidenceError()


@lru_cache(maxsize=4)
def _contracts(root: Path):
    folder = root / "contracts"
    docs = {}
    for name in {name for name, _ in _RESPONSES.values()}:
        docs[name] = yaml.safe_load((folder / name).read_text(encoding="utf-8"))
    for path in folder.glob("*.schema.json"):
        docs[path.name] = json.loads(path.read_text(encoding="utf-8"))
    registry = Registry().with_resources([
        (doc.get("$id", _BASE + name), DRAFT202012.create_resource(doc))
        for name, doc in docs.items()
    ])
    refs = {
        "evidence": _BASE + "common.schema.json#/$defs/EvidenceRef",
        "election_id": _BASE + "common.schema.json#/$defs/ElectionId",
        "finding_id": _BASE + "common.schema.json#/$defs/FindingId",
        "submission": _BASE + "finding.schema.json#/$defs/FindingSubmission",
        "report": _BASE + "audit-report.schema.json#/$defs/AuditReportSubmission",
    }
    for key, (name, path) in _RESPONSES.items():
        escaped = path.replace("~", "~0").replace("/", "~1")
        refs[key] = _BASE + name + "#/paths/" + escaped + "/get/responses/200/content/application~1json/schema"
    validators = {
        key: Draft202012Validator({"$ref": ref}, registry=registry, format_checker=FormatChecker())
        for key, ref in refs.items()
    }
    fields = frozenset(docs["finding.schema.json"]["$defs"]["FindingBody"]["properties"])
    return validators, fields


def _validate(value, kind: str):
    try:
        canonical(value)
        identifier = value.get("ref") if kind == "evidence" and isinstance(value, dict) else value
        if kind in {"evidence", "election_id", "finding_id"} and (
                not isinstance(identifier, str) or not identifier.isascii() or
                any(ord(char) < 33 or ord(char) > 126 for char in identifier)):
            raise _invalid()
        if not _contracts(reference_root())[0][kind].is_valid(value):
            raise _invalid()
    except EvidenceError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise _invalid() from None


def finding_submission(finding: dict) -> dict:
    """Extract immutable signed fields, excluding mutable Core review metadata."""
    if not isinstance(finding, dict):
        raise _invalid()
    fields = _contracts(reference_root())[1]
    submission = {key: copy.deepcopy(value) for key, value in finding.items() if key in fields}
    _validate(submission, "submission")
    return submission


def finding_fingerprint(finding: dict) -> str:
    """SHA-256 of the canonical FindingSubmission, stable across review updates."""
    return hashlib.sha256(canonical(finding_submission(finding))).hexdigest()


def validate_report_schema(report: dict) -> None:
    """Validate the submission schema locally; this does not resolve evidence."""
    _validate(report, "report")
    if report["trace"]["steps"] > 20 or len(report["trace"]["tool_calls"]) > 20:
        raise EvidenceError("STEP_LIMIT", "limit")


def _unique_keys(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON key")
    return value


def _contains_private_key(value) -> bool:
    if isinstance(value, dict):
        return any((key == "private_key" and item is not None) or _contains_private_key(item)
                   for key, item in value.items())
    return isinstance(value, list) and any(_contains_private_key(item) for item in value)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EvidenceClient:
    """HTTP readers supplied with AGENT_KEY; production clients use trust_env=False.

    Clients must have root HTTP(S) base URLs and the same X-Service-Key. Every
    request is a locally constructed GET and explicitly disables redirects.
    The socket timeout is additionally bounded by a wall-clock deadline: at
    most one daemon request can remain active after a deadline. A later call
    retries only once that operation has unwound, preventing thread buildup.
    """

    def __init__(self, core: httpx.Client, gateway: httpx.Client, *, page_size: int = 100,
                 max_pages: int = 100, max_bytes: int = 2 * 1024 * 1024,
                 timeout_seconds: float = 10):
        if (type(page_size) is not int or not 1 <= page_size <= 1000 or
                type(max_pages) is not int or not 1 <= max_pages <= 10000 or
                type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024 or
                isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or
                not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 10):
            raise ValueError("invalid audit evidence bounds")
        for client in (core, gateway):
            url = client.base_url
            if (url.scheme not in {"http", "https"} or not url.host or url.username or url.password
                    or url.query or url.fragment or url.path not in {"", "/"}):
                raise ValueError("invalid audit evidence base URL")
        core_key = core.headers.get("X-Service-Key")
        if not core_key or core_key != gateway.headers.get("X-Service-Key"):
            raise ValueError("audit clients require the same AGENT_KEY")
        self.core, self.gateway = core, gateway
        self.page_size, self.max_pages, self.max_bytes = page_size, max_pages, max_bytes
        self.timeout_seconds = float(timeout_seconds)
        self._active: threading.Thread | None = None
        self._lock = threading.Lock()
        # Build local-only validators before starting network deadlines.
        self.validators = _contracts(reference_root())[0]

    def _read_sync(self, source: str, schema: str, path: str, params) -> dict:
        client = self.core if source == "core" else self.gateway
        try:
            with client.stream("GET", path, params=params, follow_redirects=False,
                               timeout=self.timeout_seconds) as response:
                if response.status_code != 200:
                    status = response.status_code
                    if status == 404:
                        raise EvidenceError("TOOL_ERROR", "not_found", retryable=True)
                    if status >= 500 or status in {408, 425, 429}:
                        raise EvidenceError("TOOL_ERROR", "unavailable", retryable=True)
                    raise _invalid()
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > self.max_bytes:
                        raise _invalid()
                    raw.extend(chunk)
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
            _validate(value, schema)
            # Even a mistakenly privileged server response is not accepted.
            if _contains_private_key(value):
                raise _invalid()
            return value
        except EvidenceError:
            raise
        except httpx.TimeoutException:
            raise EvidenceError("TIMEOUT", "unavailable", retryable=True) from None
        except httpx.HTTPError:
            raise EvidenceError("TOOL_ERROR", "unavailable", retryable=True) from None
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            raise _invalid() from None

    def _read(self, source: str, schema: str, path: str, params) -> dict:
        # No value from a response is ever interpreted as a path or URL.
        if source not in {"core", "gateway"} or not path.startswith("/") or path.startswith("//"):
            raise _invalid()
        outcome: queue.Queue = queue.Queue(maxsize=1)

        def operation():
            try:
                result = (True, self._read_sync(source, schema, path, params))
            except EvidenceError as exc:
                result = (False, exc)
            except Exception:
                result = (False, EvidenceError("TOOL_ERROR", "unavailable", retryable=True))
            finally:
                with self._lock:
                    self._active = None
            outcome.put(result)

        with self._lock:
            if self._active is not None:
                raise EvidenceError("TIMEOUT", "unavailable", retryable=True)
            self._active = threading.Thread(target=operation, name="audit-evidence-get", daemon=True)
            self._active.start()
        try:
            success, result = outcome.get(timeout=self.timeout_seconds)
        except queue.Empty:
            raise EvidenceError("TIMEOUT", "unavailable", retryable=True) from None
        if not success:
            raise result from None
        return result

    def iter_findings(self, election_id: str | None = None) -> Iterator[dict]:
        """Discover FAIL/INCONCLUSIVE stored findings; every sweep starts at page one.

        Discovery is outside an individual investigation's twenty-step budget,
        but has its own page/byte/time bounds. Core's has_report stays false until
        report storage is implemented, so the worker must persist deduplication.
        """
        if election_id is not None:
            _validate(election_id, "election_id")
        cursor, cursors, ids = None, set(), set()
        for _ in range(self.max_pages):
            params = [("result", "FAIL"), ("result", "INCONCLUSIVE"),
                      ("has_report", "false"), ("limit", str(self.page_size))]
            if election_id is not None:
                params.append(("election_id", election_id))
            if cursor is not None:
                params.append(("cursor", cursor))
            page = self._read("core", "findings", "/internal/v1/findings", params)
            batch, cursor = page["items"], page["next_cursor"]
            if (len(batch) > self.page_size or
                    cursor is not None and (not batch or not cursor or len(cursor) > 4096 or cursor in cursors)):
                raise _invalid()
            for finding in batch:
                fid = finding["finding_id"]
                if (fid in ids or finding["result"] not in {"FAIL", "INCONCLUSIVE"} or
                        election_id is not None and finding["election_id"] != election_id):
                    raise _invalid()
                ids.add(fid)
                yield finding
            if cursor is None:
                return
            cursors.add(cursor)
        raise EvidenceError("STEP_LIMIT", "limit", retryable=True)

    def begin(self, election_id: str, checkpoint: int | None = None, *, max_steps: int = 20):
        return EvidenceSession(self, election_id, checkpoint, max_steps=max_steps)


class EvidenceSession:
    """One election/checkpoint investigation, with shared lookup caching."""

    def __init__(self, client: EvidenceClient, election_id: str, checkpoint: int | None, *, max_steps: int = 20):
        _validate(election_id, "election_id")
        if (checkpoint is not None and (type(checkpoint) is not int or not 0 <= checkpoint <= 9007199254740991)
                or type(max_steps) is not int or not 1 <= max_steps <= 20):
            raise ValueError("invalid evidence investigation bounds")
        self.client, self.election_id, self.checkpoint = client, election_id, checkpoint
        self.max_steps = max_steps
        self._calls: list[dict] = []
        self._resolved: set[tuple[str, str]] = set()
        self._cache: dict[tuple, dict] = {}
        self._started = time.monotonic()

    def _tool(self, source, schema, path, params, tool, args=None):
        key = (source, schema, path, tuple(sorted(params.items())))
        if key in self._cache:
            return self._cache[key]
        if len(self._calls) >= self.max_steps:
            raise EvidenceError("STEP_LIMIT", "limit")
        record = {"tool": tool, "called_at": _now(), "ok": False}
        if args:
            record["args"] = args
        self._calls.append(record)
        value = self.client._read(source, schema, path, params)
        record["ok"] = True
        record["result_count"] = len(value["items"]) if isinstance(value.get("items"), list) else 1
        self._cache[key] = value
        return value

    def _scope(self, value: dict, *, checkpoint: bool = False):
        if value.get("election_id") != self.election_id:
            raise _invalid()
        if checkpoint and (self.checkpoint is None or value["checkpoint"] > self.checkpoint):
            raise _invalid()

    def get_finding(self, finding_id: str) -> dict:
        before = len(self._calls)
        try:
            return self._get_finding(finding_id)
        except EvidenceError:
            if len(self._calls) > before:
                self._calls[-1]["ok"] = False
            raise

    def _get_finding(self, finding_id: str) -> dict:
        _validate(finding_id, "finding_id")
        value = self._tool("core", "finding", "/internal/v1/findings/" + finding_id,
                           {}, "get_finding")
        if value["finding_id"] != finding_id:
            raise _invalid()
        if self.checkpoint is None:
            self.checkpoint = value["checkpoint"]
        self._scope(value, checkpoint=True)
        self._resolved.add(("finding", finding_id))
        return copy.deepcopy(value)

    def _event(self, event_id: str) -> dict:
        value = self._tool("gateway", "event", "/v1/events/" + event_id,
                           {}, "get_ledger_event")
        if value["event_id"] != event_id:
            raise _invalid()
        self._scope(value, checkpoint=True)
        return value

    def _snapshot(self, name: str, checkpoint: int):
        page = self._tool("core", "view", "/internal/v1/views/" + name,
                          {"election_id": self.election_id, "checkpoint": checkpoint, "limit": 1},
                          "query_view", {"view": name, "checkpoint": checkpoint})
        if (page["view"], page["election_id"], page["checkpoint"]) != (name, self.election_id, checkpoint):
            raise _invalid()
        if page["snapshot_hash"] is None or len(page["rows"]) > 1:
            raise _invalid()
        if (any(row["view"] != name for row in page["rows"]) or
                page["total_rows"] < len(page["rows"]) or
                (page["total_rows"] == 0) != (len(page["rows"]) == 0) or
                (page["total_rows"] > 1) != (page["next_cursor"] is not None)):
            raise _invalid()
        commits = self._tool("core", "checkpoints", "/internal/v1/checkpoints",
                             {"election_id": self.election_id}, "list_checkpoints")
        rows = commits["items"]
        ks = [row["checkpoint"] for row in rows]
        if ks != sorted(set(ks)) or any(k >= commits["open_checkpoint"] for k in ks):
            raise _invalid()
        matching = [row for row in rows if row["checkpoint"] == checkpoint]
        if len(matching) != 1 or matching[0]["ledger_status"] != "ACCEPTED":
            raise EvidenceError("TOOL_ERROR", "unavailable", retryable=True)
        event = self._event(matching[0]["event_id"])
        if (event["type"] != "CHECKPOINT_COMMITTED" or event["checkpoint"] != checkpoint or
                event["payload"]["checkpoint"] != checkpoint or
                event["payload"]["reason"] != matching[0]["reason"]):
            raise _invalid()
        tables = event["payload"]["tables"]
        if len({row["table"] for row in tables}) != len(tables) or not any(row["table"] == name for row in tables):
            raise _invalid()
        # Deliberately do not require page hash/count to equal committed values:
        # their disagreement is precisely the R5 evidence being explained.

    def resolve(self, ref: dict) -> None:
        before = len(self._calls)
        try:
            self._resolve(ref)
        except EvidenceError:
            if len(self._calls) > before:
                self._calls[-1]["ok"] = False
            raise

    def _resolve(self, ref: dict) -> None:
        _validate(ref, "evidence")
        if self.checkpoint is None:
            raise _invalid()
        kind, identifier = ref["kind"], ref["ref"]
        if (kind, identifier) in self._resolved:
            return
        if kind == "finding":
            self.get_finding(identifier)
        elif kind == "ledger_event":
            self._event(identifier)
        elif kind in {"ledger_rejection", "anchor", "proposal"}:
            schema, plural, key, tool = {
                "ledger_rejection": ("rejection", "rejections", "rejection_id", "get_ledger_rejections"),
                "anchor": ("anchor", "anchors", "anchor_id", "get_anchor"),
                "proposal": ("proposal", "proposals", "proposal_id", "get_proposal"),
            }[kind]
            value = self._tool("gateway", schema, "/v1/" + plural + "/" + identifier, {}, tool)
            if value[key] != identifier:
                raise _invalid()
            self._scope(value, checkpoint=kind == "ledger_rejection")
        elif kind in {"view_row", "snapshot"}:
            subject, at = identifier.rsplit("@", 1)
            checkpoint = int(at)
            if checkpoint > self.checkpoint or checkpoint > 9007199254740991:
                raise _invalid()
            if kind == "snapshot":
                self._snapshot(subject, checkpoint)
            else:
                view, row_key = subject.split(":", 1)
                path = "/internal/v1/views/" + view + "/rows/" + quote(row_key, safe="")
                row = self._tool("core", "row", path,
                                 {"election_id": self.election_id, "checkpoint": checkpoint},
                                 "get_view_row", {"view": view, "checkpoint": checkpoint})
                if row["view"] != view or row["row_key"] != row_key:
                    raise _invalid()
        elif kind == "service_log":
            service, log_id = identifier.split(":", 1)
            value = self._tool("core", "log", "/internal/v1/service-logs/" + service + "/" + log_id,
                               {}, "get_service_log", {"service": service})
            if value["service"] != service or value["log_id"] != log_id:
                raise _invalid()
            # Untagged logs are global service evidence, not election attribution.
            logged_election = value.get("context", {}).get("election_id")
            if logged_election is not None and logged_election != self.election_id:
                raise _invalid()
        else:
            raise _invalid()
        self._resolved.add((kind, identifier))

    def trace(self) -> dict:
        return {"steps": len(self._calls), "tool_calls": copy.deepcopy(self._calls),
                "duration_ms": max(0, int((time.monotonic() - self._started) * 1000))}


def validate_report_live(report: dict, client: EvidenceClient) -> dict:
    """Re-fetch the report's subject and every cited/counter-evidence reference."""
    validate_report_schema(report)
    session = client.begin(report["election_id"])
    finding = session.get_finding(report["finding_id"])
    if finding["result"] not in {"FAIL", "INCONCLUSIVE"}:
        raise _invalid()
    refs = {(ref["kind"], ref["ref"]): ref
            for hypothesis in report["hypotheses"]
            for field in ("evidence_refs", "counter_evidence_refs")
            for ref in hypothesis.get(field, [])}
    for key in sorted(refs):
        session.resolve(refs[key])
    return {"valid": True, "unique_references": len(refs),
            "steps": session.trace()["steps"], "verification": "reference_existence_and_scope"}
