"""Internal endpoints for the Rule Engine (ruleKey), Audit Agent (agentKey) and Gateway (gatewayKey)."""
import base64

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import findings, timeutil, views
from app.auth import require_service
from app.errors import Problem
from app.hashing import snapshot_hash
from app.models import AlertIn
from app.store import load_election, raise_alert
from app.timeutil import from_dt, iso
from app.tx import run

router = APIRouter(prefix="/internal/v1", tags=["internal"])
READERS = require_service("rule", "agent")
LEDGER_STATUS = {"PENDING": "PENDING", "ACCEPTED": "ACCEPTED", "DUPLICATE": "ACCEPTED", "REJECTED": "REJECTED",
                 "CONFLICT": "REJECTED"}
ALERT_KINDS = {"rule": ("AUDIT_DELAYED", "LEDGER_UNAVAILABLE", "CHAIN_CONFIG_MISMATCH"), "gateway": ("ANCHOR_REJECTED",)}
ALERT_SOURCE = {"rule": "rule-engine", "gateway": "ledger-gateway"}


def _special(conn, eid: str, reason: str):
    return conn.execute(text("SELECT checkpoint FROM credential.checkpoints WHERE election_id = :e AND reason = :r "
                             "ORDER BY checkpoint DESC LIMIT 1"), {"e": eid, "r": reason}).scalar()


@router.get("/elections")
def list_elections(status: list[str] | None = Query(default=None), svc: str = Depends(READERS)):
    def go(conn):
        items = []
        for (eid,) in conn.execute(text("SELECT election_id FROM credential.elections ORDER BY election_id")):
            e = load_election(conn, eid)
            if (status and e["status"] not in status) or (not status and e["status"] == "DRAFT"):
                continue
            last = conn.execute(text("SELECT max(checkpoint) FROM credential.checkpoints WHERE election_id = :e"),
                                {"e": eid}).scalar()
            items.append({"election_id": eid, "status": e["status"], "open_checkpoint": e["open_checkpoint"],
                          "last_committed_checkpoint": last, "close_final_checkpoint": _special(conn, eid, "CLOSE_FINAL"),
                          "tally_checkpoint": _special(conn, eid, "TALLY")})
        return {"items": items}
    return run(go)


@router.get("/checkpoints")
def list_checkpoints(election_id: str, svc: str = Depends(READERS)):
    def go(conn):
        e = load_election(conn, election_id)
        rows = conn.execute(text("SELECT c.checkpoint, c.reason, c.event_id, o.status FROM credential.checkpoints c "
                                 "JOIN credential.outbox o ON o.event_id = c.event_id WHERE c.election_id = :e "
                                 "ORDER BY c.checkpoint"), {"e": election_id})
        return {"open_checkpoint": e["open_checkpoint"],
                "items": [{"checkpoint": r.checkpoint, "reason": r.reason, "event_id": r.event_id,
                           "ledger_status": LEDGER_STATUS[r.status]} for r in rows]}
    return run(go)


def _committed(conn, eid: str, checkpoint: int | None) -> int:
    if checkpoint is None:
        k = conn.execute(text("SELECT max(checkpoint) FROM credential.checkpoints WHERE election_id = :e"),
                         {"e": eid}).scalar()
    else:
        k = conn.execute(text("SELECT checkpoint FROM credential.checkpoints WHERE election_id = :e "
                              "AND checkpoint = :k"), {"e": eid, "k": checkpoint}).scalar()
    if k is None:
        raise Problem(404, "CHECKPOINT_NOT_FOUND")
    return k


def view_page(view: str, eid: str, checkpoint: int | None, limit: int, cursor: str | None, reveal_key: bool) -> dict:
    if view not in views.VIEWS:
        raise Problem(404, "NOT_FOUND")
    if not 1 <= limit <= 1000:
        raise Problem(400, "VALIDATION_ERROR", "limit")

    def go(conn):
        load_election(conn, eid)
        k = _committed(conn, eid, checkpoint)
        rows = views.read(conn, view, eid, k, reveal_key)
        try:
            after = base64.urlsafe_b64decode(cursor.encode()).decode() if cursor else None
        except (ValueError, UnicodeDecodeError):
            raise Problem(400, "VALIDATION_ERROR", "cursor") from None
        page_from = [r for r in rows if after is None or r["row_key"] > after]
        page = page_from[:limit]
        nxt = (base64.urlsafe_b64encode(page[-1]["row_key"].encode()).decode()
               if len(page_from) > limit else None)
        return {"view": view, "election_id": eid, "checkpoint": k, "total_rows": len(rows),
                "snapshot_hash": None if view == "election_config" else snapshot_hash(rows),
                "rows": page, "next_cursor": nxt}
    return run(go)


@router.get("/views/{view}")
def read_view(view: str, election_id: str, checkpoint: int | None = None, limit: int = 100,
              cursor: str | None = None, svc: str = Depends(READERS)):
    return view_page(view, election_id, checkpoint, limit, cursor, reveal_key=svc == "rule")


@router.get("/views/{view}/rows/{row_key}")
def read_view_row(view: str, row_key: str, election_id: str, checkpoint: int, svc: str = Depends(READERS)):
    if view not in views.VIEWS:
        raise Problem(404, "NOT_FOUND")

    def go(conn):
        k = _committed(conn, election_id, checkpoint)
        for r in views.read(conn, view, election_id, k, svc == "rule"):
            if r["row_key"] == row_key:
                return r
        raise Problem(404, "NOT_FOUND")
    return run(go)


@router.post("/findings")
def store_finding(body: dict, svc: str = Depends(require_service("rule"))):
    status = run(lambda c: findings.store(c, body))
    return JSONResponse({}, status_code=status)


@router.get("/findings")
def list_findings(election_id: str | None = None, result: list[str] | None = Query(default=None),
                  has_report: bool | None = None, limit: int = 100, cursor: str | None = None,
                  svc: str = Depends(READERS)):
    if not 1 <= limit <= 1000:
        raise Problem(400, "VALIDATION_ERROR", "limit")

    def go(conn):
        sql = "SELECT * FROM credential.findings WHERE true"
        params = {}
        if election_id:
            sql += " AND election_id = :e"
            params["e"] = election_id
        if result:
            sql += " AND body->>'result' = ANY(:r)"
            params["r"] = result
        if cursor:
            sql += " AND finding_id > :c"
            params["c"] = cursor
        sql += " ORDER BY finding_id LIMIT :n"
        params["n"] = limit + 1
        rows = conn.execute(text(sql), params).all()
        # AI reports are not stored before week 8, so has_report=true matches nothing yet
        if has_report:
            rows = []
        page = rows[:limit]
        return {"items": [findings.to_stored(r) for r in page],
                "next_cursor": page[-1].finding_id if len(rows) > limit else None}
    return run(go)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, svc: str = Depends(READERS)):
    def go(conn):
        row = conn.execute(text("SELECT * FROM credential.findings WHERE finding_id = :f"), {"f": finding_id}).first()
        if row is None:
            raise Problem(404, "NOT_FOUND")
        return findings.to_stored(row)
    return run(go)


@router.post("/audit-alerts", status_code=202)
def raise_audit_alert(body: AlertIn, svc: str = Depends(require_service("rule", "gateway"))):
    if body.kind not in ALERT_KINDS[svc]:
        raise Problem(403, "FORBIDDEN", "this service may not raise this alert kind")

    def go(conn):
        load_election(conn, body.election_id)
        raise_alert(conn, body.election_id, body.checkpoint, body.kind, ALERT_SOURCE[svc], timeutil.clock.now(),
                    body.detail)
    run(go)
    return JSONResponse({}, status_code=202)


def alerts_of(election_id: str) -> dict:
    def go(conn):
        load_election(conn, election_id)
        rows = conn.execute(text("SELECT * FROM credential.audit_alerts WHERE election_id = :e "
                                 "ORDER BY raised_at DESC, checkpoint DESC"), {"e": election_id})
        out = []
        for r in rows:
            a = {"election_id": r.election_id, "checkpoint": r.checkpoint, "source": r.source, "kind": r.kind,
                 "raised_at": iso(from_dt(r.raised_at))}
            if r.detail:
                a["detail"] = r.detail
            out.append(a)
        return {"items": out}
    return run(go)


@router.get("/audit-alerts")
def list_audit_alerts(election_id: str, svc: str = Depends(READERS)):
    return alerts_of(election_id)
