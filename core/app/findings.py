"""Finding bodies (POST /internal/v1/findings). Single acceptance condition: schema-valid FindingSubmission, a
FINDING_RECORDED with the same finding_id exists at the Gateway, and its finding_hash equals Hc(body)."""
from sqlalchemy import text

from app import hashing, schemas
from app.errors import Problem
from app.gateway import GatewayUnavailable, get_gateway
from app.store import jsonb


def store(conn, body: dict) -> int:
    """Returns 201 (stored) or 200 (identical resubmission)."""
    errs = schemas.errors("finding.schema.json", "FindingSubmission", body)
    if errs:
        raise Problem(400, "VALIDATION_ERROR", "; ".join(errs[:5]))
    fid, eid = body["finding_id"], body["election_id"]
    finding_hash = hashing.Hc(body)
    existing = conn.execute(text("SELECT finding_hash FROM credential.findings WHERE finding_id = :f"),
                            {"f": fid}).first()
    if existing is not None:
        if existing.finding_hash == finding_hash:
            return 200
        raise Problem(409, "CONFLICT", "different body for this finding_id")
    if conn.execute(text("SELECT 1 FROM credential.elections WHERE election_id = :e"), {"e": eid}).first() is None:
        raise Problem(404, "NOT_FOUND", "unknown election")
    try:
        record = get_gateway().finding_record(eid, fid)
    except GatewayUnavailable:
        raise Problem(503, "LEDGER_UNAVAILABLE", "Gateway unreachable; retry with the same body") from None
    if record is None:
        raise Problem(503, "LEDGER_UNAVAILABLE", "FINDING_RECORDED not indexed yet; retry with the same body")
    recorded = record["recorded"]
    if recorded["payload"]["finding_hash"] != finding_hash:
        raise Problem(422, "FINDING_NOT_RECORDED", "Hc(body) differs from the recorded finding_hash")
    review = "NOT_REQUIRED" if body["result"] == "PASS" else "PENDING"
    inserted = conn.execute(text(
        "INSERT INTO credential.findings (finding_id, election_id, body, finding_hash, recorded_event_id, review_status) "
        "VALUES (:f, :e, CAST(:b AS jsonb), :h, :ev, :r) ON CONFLICT (finding_id) DO NOTHING RETURNING finding_id"),
        {"f": fid, "e": eid, "b": jsonb(body), "h": finding_hash, "ev": recorded["event_id"], "r": review}).first()
    if inserted is None:   # a concurrent identical POST stored it first (a different body cannot match the record)
        return 200
    return 201


def to_stored(row) -> dict:
    """Stored Finding = FindingSubmission + review + recorded_event_id + evidence_check (finding.schema.json).
    Reviews arrive with the review relay (week 5); evidence references are resolved later (status PENDING until then)."""
    return dict(row.body) | {"review": {"status": row.review_status, "reviews": []},
                             "recorded_event_id": row.recorded_event_id,
                             "evidence_check": {"status": row.evidence_status}}
