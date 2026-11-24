"""Durable local report journal and atomic exports for the template Audit Agent.

The SQLite journal commits the exact report bytes before file publication. A
restart republishes missing exports using those same bytes and identifiers.
There is deliberately no Core report write: report storage is deferred in D-28.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from .hashing import canonical


class ReportStoreError(Exception):
    """A safe category; never embeds paths, report bodies or credentials."""


class FindingConflict(ReportStoreError):
    """An immutable finding ID was observed with different submission bytes."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_export(path: Path, content: bytes) -> None:
    """Publish only closed, fsynced files, including on Windows."""
    if path.exists():
        if path.read_bytes() != content:
            raise ReportStoreError("An existing report export differs from its journal")
        return
    handle, temporary = tempfile.mkstemp(prefix=".audit-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _markdown(report: dict) -> bytes:
    """A companion to the schema-valid JSON, not a second evidence source."""
    def literal(value):
        # JSON quoting keeps arbitrary punctuation on one line and avoids
        # treating any source string as Markdown or an executable hyperlink.
        return "`" + json.dumps(value, ensure_ascii=True).replace("`", "\\u0060") + "`"

    lines = ["# Audit report — template, not AI", "", "This report is advisory. Human review is required.", "",
             "| Field | Value |", "|---|---|",
             *[f"| {label} | {literal(report[key])} |" for label, key in
               [("Report", "report_id"), ("Finding", "finding_id"), ("Election", "election_id"),
                ("Generated (UTC)", "created_at"), ("Report status", "status"), ("Risk", "risk_level")]], ""]
    if report.get("abort_reason"):
        lines += ["Abort reason: " + literal(report["abort_reason"]), ""]
    lines += ["## Possible causes", ""]
    if not report["hypotheses"]:
        lines += ["No cause was assigned. The report status and limitations explain the remaining uncertainty.", ""]
    for hypothesis in report["hypotheses"]:
        lines += ["### " + literal(hypothesis["cause_code"]), "", literal(hypothesis["explanation"]), "",
                  "Likelihood: " + literal(hypothesis["likelihood"]), "", "Evidence references:", ""]
        lines += ["- " + literal(ref["kind"]) + " " + literal(ref["ref"])
                  for ref in hypothesis["evidence_refs"]]
        lines.append("")
    lines += ["## Additional checks", ""]
    lines += ["- " + literal(check) for check in report["additional_checks"]]
    lines += ["", "## Suggested human actions", ""]
    lines += ["- " + literal(item["urgency"]) + ": " + literal(item["action"])
              for item in report["recommended_actions"]]
    lines += ["", "## Limitations", "", literal(report["limitations"]), ""]
    return "\n".join(lines).encode("utf-8")


class ReportStore:
    """One writer, immutable finding identity, bounded retries and durable files."""
    def __init__(self, state_dir: Path, binding: dict, *, report_dir: Path | None = None):
        self.state_dir = Path(state_dir)
        self.report_dir = Path(report_dir) if report_dir is not None else self.state_dir / "reports"
        self.metadata_dir = self.report_dir / "metadata"
        self._lock = None
        self.db = None
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.metadata_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self._acquire_lock()
            self.db = sqlite3.connect(self.state_dir / "reports.sqlite3", timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS seen (finding TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,"
                                " first_seen_ms INTEGER NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS attempts (finding TEXT NOT NULL, policy TEXT NOT NULL,"
                                " attempt INTEGER NOT NULL, report_id TEXT UNIQUE NOT NULL, status TEXT NOT NULL,"
                                " body TEXT NOT NULL, metadata TEXT NOT NULL, digest TEXT NOT NULL,"
                                " next_retry_ms INTEGER, PRIMARY KEY(finding, policy, attempt))")
                identity = canonical(binding).decode("utf-8")
                self.db.execute("INSERT OR IGNORE INTO identity VALUES (1,?)", (identity,))
                if self.db.execute("SELECT body FROM identity WHERE id=1").fetchone()[0] != identity:
                    raise ReportStoreError("State belongs to a different service deployment")
        except BaseException:
            self.close()
            raise

    def _acquire_lock(self):
        self._lock = (self.state_dir / "writer.lock").open("a+b")
        self._lock.seek(0, os.SEEK_END)
        if self._lock.tell() == 0:
            self._lock.write(b"0")
            self._lock.flush()
        self._lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lock.close()
            self._lock = None
            raise ReportStoreError("Another audit-agent writer owns this state") from None

    def observe(self, finding_id: str, fingerprint: str, now_ms: int) -> int:
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO seen VALUES (?,?,?)", (finding_id, fingerprint, now_ms))
        row = self.db.execute("SELECT fingerprint,first_seen_ms FROM seen WHERE finding=?", (finding_id,)).fetchone()
        if row["fingerprint"] != fingerprint:
            raise FindingConflict("Finding ID changed its immutable submission")
        return row["first_seen_ms"]

    def last_attempt(self, finding_id: str, policy: str):
        row = self.db.execute("SELECT * FROM attempts WHERE finding=? AND policy=? ORDER BY attempt DESC LIMIT 1",
                              (finding_id, policy)).fetchone()
        if row is not None:
            self._validate_record(row)
        return row

    def due(self, finding_id: str, policy: str, now_ms: int, max_attempts: int) -> bool:
        previous = self.last_attempt(finding_id, policy)
        if previous is None:
            return True
        return (previous["status"] == "ABORTED" and previous["attempt"] < max_attempts
                and previous["next_retry_ms"] is not None and now_ms >= previous["next_retry_ms"])

    def save(self, report: dict, metadata: dict, *, policy: str, next_retry_ms: int | None):
        from .audit_report import validate_report
        validate_report(report)
        body = canonical(report).decode("utf-8")
        metadata_body = canonical(metadata).decode("utf-8")
        previous = self.last_attempt(report["finding_id"], policy)
        attempt = 1 if previous is None else previous["attempt"] + 1
        row = {"finding": report["finding_id"], "policy": policy, "attempt": attempt,
               "report_id": report["report_id"], "status": report["status"], "body": body,
               "metadata": metadata_body, "next_retry_ms": next_retry_ms}
        row["digest"] = self._record_digest(row)
        self._validate_record(row)
        with self.db:
            self.db.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?,?,?)",
                            (report["finding_id"], policy, attempt, report["report_id"], report["status"],
                             body, metadata_body, row["digest"], next_retry_ms))
        # A failure here leaves a committed record that recover() republishes.
        self._export(self.last_attempt(report["finding_id"], policy))

    @staticmethod
    def _record_digest(row):
        # Bind provenance and retry/dedup columns as well as report bytes.
        # This detects corruption; it is not a signature against a malicious
        # operator who can replace both the data and its local checksum.
        return _digest(canonical({name: row[name] for name in
                                  ("finding", "policy", "attempt", "report_id", "status", "body",
                                   "metadata", "next_retry_ms")}))

    def _validate_record(self, row):
        from .audit_report import validate_report
        if self._record_digest(row) != row["digest"]:
            raise ReportStoreError("Journal report or metadata digest mismatch")
        report = json.loads(row["body"])
        metadata = json.loads(row["metadata"])
        validate_report(report)
        if (report["report_id"] != row["report_id"] or report["finding_id"] != row["finding"]
                or report["status"] != row["status"] or metadata.get("format_version") != 1
                or metadata.get("report_id") != row["report_id"] or metadata.get("finding_id") != row["finding"]
                or metadata.get("generation_policy_sha256") != row["policy"]
                or type(metadata.get("attempt")) is not int or metadata["attempt"] != row["attempt"]
                or metadata.get("generated_at") != report["created_at"]
                or metadata.get("official_scenario_result") is not False or metadata.get("ai_generated") is not False
                or metadata.get("core_storage_to_report_ms") is not None
                or metadata.get("reference_validation") != ("aborted" if report["status"] == "ABORTED" else "resolved")
                or row["next_retry_ms"] is not None and
                   (type(row["next_retry_ms"]) is not int or row["next_retry_ms"] < 0 or row["status"] != "ABORTED")):
            raise ReportStoreError("Journal report identity mismatch")
        return report

    def _export(self, row):
        report = self._validate_record(row)
        body = row["body"].encode("utf-8")
        # The validated ReportId fixes the filename; no API value supplies a path.
        report_id = report["report_id"]
        _atomic_export(self.report_dir / (report_id + ".json"), body + b"\n")
        _atomic_export(self.report_dir / (report_id + ".md"), _markdown(report))
        _atomic_export(self.metadata_dir / (report_id + ".json"), row["metadata"].encode("utf-8") + b"\n")

    def recover(self):
        rows = self.db.execute("SELECT * FROM attempts ORDER BY rowid").fetchall()
        for row in rows:
            self._export(row)
        return len(rows)

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._lock is not None:
            try:
                self._lock.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self._lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._lock.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock.close()
                self._lock = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
