"""Ledger events (contracts/ledger-events.schema.json) written to the outbox in the caller's transaction.

System events get a gap-free seq per election (counter table, never a SEQUENCE) and exact times; voter events get
random evr_ IDs, bucketed times and no seq (README "Consistency model", "Shared conventions").
"""
from sqlalchemy import text

from app import hashing
from app.ids import random_id, ulid
from app.store import jsonb
from app.timeutil import floor_bucket, iso, system_bucket_start, to_dt

SYSTEM = {"kind": "system"}
VOTER = {"kind": "voter_anonymous"}


def staff_actor(staff) -> dict:
    return {"kind": staff.role if staff.role in ("admin", "approver") else "admin",
            "org_id": staff.org_id, "user_id": staff.user_id}


def _next_seq(conn, election_id: str) -> int:
    return conn.execute(text("UPDATE credential.seq_counters SET last_seq = last_seq + 1 WHERE election_id = :e "
                             "RETURNING last_seq"), {"e": election_id}).scalar_one()


def _insert(conn, event: dict, kind: str, bucket_start: int) -> dict:
    conn.execute(text("INSERT INTO credential.outbox (event_id, election_id, kind, seq, bucket_start, event, payload_hash) "
                      "VALUES (:id, :e, :kind, :seq, :b, CAST(:ev AS jsonb), :ph)"),
                 {"id": event["event_id"], "e": event["election_id"], "kind": kind, "seq": event.get("seq"),
                  "b": to_dt(bucket_start), "ev": jsonb(event), "ph": event["payload_hash"]})
    return event


def emit_system(conn, e: dict, type_: str, payload: dict, occurred_at: int, actor: dict = SYSTEM) -> dict:
    """Core system event at Core's open checkpoint. A boundary-scheduled event passes the logical boundary time."""
    event = {
        "event_id": ulid("evt"), "schema_version": "1", "election_id": e["election_id"], "type": type_,
        "source": "core", "seq": _next_seq(conn, e["election_id"]), "checkpoint": e["open_checkpoint"],
        "occurred_at": iso(occurred_at), "time_precision": "exact", "actor": actor,
        "payload": payload, "payload_hash": hashing.Hc(payload),
    }
    return _insert(conn, event, "system", system_bucket_start(occurred_at, e["time_bucket_seconds"]))


def emit_voter(conn, e: dict, type_: str, payload: dict, t: int, event_id: str | None = None) -> dict:
    """TOKEN_USED / BALLOT_RECEIVED: bucketed time, random ID, no seq."""
    b = e["time_bucket_seconds"]
    bucket = floor_bucket(t, b)
    event = {
        "event_id": event_id or random_id("evr"), "schema_version": "1", "election_id": e["election_id"],
        "type": type_, "source": "core", "checkpoint": e["open_checkpoint"], "occurred_at": iso(bucket),
        "time_precision": "bucketed", "time_bucket_seconds": b, "actor": VOTER,
        "payload": payload, "payload_hash": hashing.Hc(payload),
    }
    return _insert(conn, event, "voter", bucket)
