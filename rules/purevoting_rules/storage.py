"""Durable finding outbox; canonical bodies are never rewritten after enqueue."""

from __future__ import annotations

import copy
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .findings import validate_submission
from .hashing import H, Hc, canonical


class FindingConflict(ValueError):
    """One finding ID was reused with a different body."""


class StoredBodyCorrupt(ValueError):
    """The durable body no longer matches its recorded canonical bytes/hash."""


class OutboxLocked(RuntimeError):
    """Another writer already owns this outbox."""


class OutboxPersistenceError(OSError):
    """The authoritative checkpoint could not be persisted and verified."""


class FindingStore:
    """Single-writer SQLite outbox with atomic complete-file checkpoints.

    ``get(id)['body_bytes']`` is the only body sent on publication and retries.
    For a new later-checkpoint FAIL, enqueue may add ``previous_finding_id`` to
    a private copy before first persistence. The input object is never mutated;
    callers should retrieve the finalized body with ``get`` after enqueue.

    SQL transactions execute in private memory. Before any mutation reports
    success, a complete SQLite image is written, fsynced and atomically replaced
    at ``path``. Reopening loads only that authoritative file. This avoids native
    SQLite page-overwrite/journal visibility failures observed on the execution
    workspace. An OS advisory lock permits only one writer for this path.

    No retention cleanup is performed. Closed files are ordinary standalone
    SQLite databases; no WAL/SHM files are needed. The small persistent ``.lock``
    file contains no findings and is not a journal. OS locks release on process
    exit; the file's existence does not indicate an active writer.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(":memory:")
        try:
            self._lock_fd = self._acquire_writer_lock()
        except BaseException:
            self._connection.close()
            raise
        self._closed = False
        self._failed = False
        self._connection.row_factory = sqlite3.Row
        try:
            if any(Path(str(self.path) + suffix).exists() for suffix in ("-journal", "-wal", "-shm")):
                # Never ignore or delete an old recovery journal. A native
                # reader could otherwise roll back a newly replaced image.
                raise StoredBodyCorrupt("Existing SQLite sidecars require checked recovery before use")
            if self.path.exists():
                image = self.path.read_bytes()
                if not image.startswith(b"SQLite format 3\x00"):
                    raise StoredBodyCorrupt("The outbox is not a complete SQLite checkpoint")
                if image[18:20] != b"\x01\x01":
                    raise StoredBodyCorrupt("An existing WAL database needs checked recovery before use")
                self._connection.deserialize(image)
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL UNIQUE,
                    election_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    checkpoint INTEGER NOT NULL,
                    result TEXT NOT NULL,
                    semantic_key TEXT NOT NULL UNIQUE,
                    body BLOB NOT NULL,
                    finding_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('QUEUED','REGISTERED','STORED'))
                );
                CREATE INDEX IF NOT EXISTS earlier_fail
                    ON findings(election_id, rule_id, result, checkpoint);
                """
            )
            self._persist()
        except BaseException:
            self.close()
            raise

    def _acquire_writer_lock(self) -> int:
        descriptor = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\x00")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException as exc:
            os.close(descriptor)
            if isinstance(exc, OSError):
                raise OutboxLocked("Another writer owns this outbox, or its lock is unavailable") from None
            raise
        return descriptor

    def _release_writer_lock(self) -> None:
        try:
            os.lseek(self._lock_fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._lock_fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)

    def _ensure_open(self) -> None:
        if self._failed:
            raise OutboxPersistenceError("A checkpoint failed; close and reopen the outbox before continuing")
        if self._closed:
            raise RuntimeError("The finding outbox is closed")

    def _atomic_checkpoint(self, image: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".checkpoint", dir=self.path.parent
        )
        temporary = Path(temporary_name)
        try:
            stream = os.fdopen(descriptor, "wb")
            descriptor = -1
            with stream:
                stream.write(image)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            if self.path.read_bytes() != image:
                raise OutboxPersistenceError("The persisted checkpoint differs from the committed SQLite image")
        finally:
            if descriptor != -1:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _persist(self) -> None:
        self._ensure_open()
        try:
            self._atomic_checkpoint(self._connection.serialize())
        except BaseException as exc:
            # A failed persistence attempt must never leave an apparently
            # usable instance whose memory is newer than its authoritative file.
            self._failed = True
            self._connection.close()
            if isinstance(exc, Exception):
                raise OutboxPersistenceError("Could not persist the outbox checkpoint; reopen before retrying") from exc
            raise

    @staticmethod
    def _semantic_key(body: dict[str, Any]) -> str:
        return Hc({key: body[key] for key in (
            "election_id", "rule_id", "checkpoint", "result", "observed"
        )})

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        raw = bytes(row["body"])
        try:
            body = json.loads(raw)
            if H(raw) != row["finding_hash"] or canonical(body) != raw:
                raise StoredBodyCorrupt("Stored finding bytes or hash changed")
            validate_submission(body)
            for key in ("finding_id", "election_id", "rule_id", "checkpoint", "result"):
                if body[key] != row[key]:
                    raise StoredBodyCorrupt("Stored finding index disagrees with its body")
            if FindingStore._semantic_key(body) != row["semantic_key"]:
                raise StoredBodyCorrupt("Stored finding semantic index disagrees with its body")
        except (ValueError, TypeError) as exc:
            if isinstance(exc, StoredBodyCorrupt):
                raise
            raise StoredBodyCorrupt("Stored finding is not canonical JSON") from exc
        return {
            "finding_id": row["finding_id"],
            "election_id": row["election_id"],
            "rule_id": row["rule_id"],
            "checkpoint": row["checkpoint"],
            "result": row["result"],
            "state": row["state"],
            "finding_hash": row["finding_hash"],
            "body": body,
            "body_json": raw.decode("utf-8"),
            "body_bytes": raw,
        }

    def enqueue(self, body: dict[str, Any]) -> str:
        """Persist once, or return the existing semantically identical ID.

        Reusing an existing ID with different canonical bytes is an error,
        even if its rule observations match. A different ID for an otherwise
        identical rerun is deduplicated within the same election.
        """
        self._ensure_open()
        validate_submission(body)
        candidate = copy.deepcopy(body)
        candidate_bytes = canonical(candidate)
        identity = candidate["finding_id"]
        semantic_key = self._semantic_key(candidate)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            existing = self._connection.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (identity,)
            ).fetchone()
            if existing is not None:
                stored = self._record(existing)
                if stored["body_bytes"] != candidate_bytes:
                    raise FindingConflict("The finding ID already has a different immutable body")
                self._connection.commit()
                return identity
            same_run = self._connection.execute(
                "SELECT * FROM findings WHERE semantic_key = ?", (semantic_key,)
            ).fetchone()
            if same_run is not None:
                existing_id = self._record(same_run)["finding_id"]
                self._connection.commit()
                return existing_id
            if candidate["result"] == "FAIL" and "previous_finding_id" not in candidate:
                previous = self._connection.execute(
                    """SELECT * FROM findings
                       WHERE election_id = ? AND rule_id = ? AND result = 'FAIL'
                         AND checkpoint < ?
                       ORDER BY checkpoint DESC, ordinal DESC LIMIT 1""",
                    (candidate["election_id"], candidate["rule_id"], candidate["checkpoint"]),
                ).fetchone()
                if previous is not None:
                    candidate["previous_finding_id"] = self._record(previous)["finding_id"]
            validate_submission(candidate)
            raw = canonical(candidate)
            self._connection.execute(
                """INSERT INTO findings
                   (finding_id, election_id, rule_id, checkpoint, result,
                    semantic_key, body, finding_hash, state)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'QUEUED')""",
                (identity, candidate["election_id"], candidate["rule_id"],
                 candidate["checkpoint"], candidate["result"], semantic_key,
                 sqlite3.Binary(raw), H(raw)),
            )
            self._connection.commit()
            self._persist()
            return identity
        except BaseException:
            if not self._failed:
                self._connection.rollback()
            raise

    def get(self, finding_id: str) -> dict[str, Any]:
        self._ensure_open()
        row = self._connection.execute(
            "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise KeyError(finding_id)
        return self._record(row)

    def records(self) -> list[dict[str, Any]]:
        self._ensure_open()
        return [self._record(row) for row in self._connection.execute(
            "SELECT * FROM findings ORDER BY ordinal"
        ).fetchall()]

    def pending(self) -> list[dict[str, Any]]:
        self._ensure_open()
        return [self._record(row) for row in self._connection.execute(
            "SELECT * FROM findings WHERE state != 'STORED' ORDER BY ordinal"
        ).fetchall()]

    def mark_registered(self, finding_id: str) -> None:
        record = self.get(finding_id)
        if record["state"] != "QUEUED":
            return
        with self._connection:
            self._connection.execute(
                "UPDATE findings SET state = 'REGISTERED' WHERE finding_id = ? AND state = 'QUEUED'",
                (finding_id,),
            )
        self._persist()

    def mark_stored(self, finding_id: str) -> None:
        record = self.get(finding_id)
        if record["state"] == "QUEUED":
            raise ValueError("A body must be registered before it can be marked stored")
        if record["state"] == "STORED":
            return
        with self._connection:
            self._connection.execute(
                "UPDATE findings SET state = 'STORED' WHERE finding_id = ?", (finding_id,)
            )
        self._persist()

    def close(self) -> None:
        if not self._closed:
            try:
                self._connection.close()
            finally:
                self._closed = True
                self._release_writer_lock()

    def __enter__(self) -> "FindingStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
