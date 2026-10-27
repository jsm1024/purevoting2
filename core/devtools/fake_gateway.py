"""Stateful stand-in for the Ledger Gateway, for Core tests and local runs before week 3 (not a contract
implementation: no chain, no signature checks, anchors are pretend).

    uvicorn devtools.fake_gateway:app --port 8100      (from core/)

It follows the parts of ledger-gateway.openapi.yaml that Core depends on: per-event outcomes of POST /v1/events
(seq order, DUPLICATE / CONFLICT by event_id, voter events wait for ELECTION_OPENED), the organization registry and
finding records.
"""
import hashlib
import json
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

ORGS = [
    {"org_id": "org_commission", "signer": "0x" + "a1" * 20, "is_operator": True},
    {"org_id": "org_neutral", "signer": "0x" + "b2" * 20, "is_operator": False},
    {"org_id": "org_observer", "signer": "0x" + "c3" * 20, "is_operator": False},
]


class State:
    def __init__(self):
        self.events: dict[str, dict] = {}
        self.last_seq: dict[str, int] = {}
        self.opened: set[str] = set()
        self.block = 100
        self.reject_types: set[str] = set()     # tests: force REJECTED for these event types
        self.records: dict[str, dict] = {}      # finding_id -> FINDING_RECORDED event
        self.received: list[dict] = []          # every submission, in arrival order (tests check delivery order)
        self.fail_status: int | None = None     # tests: answer POST /v1/events with this HTTP status


state = State()
app = FastAPI(title="fake ledger gateway")


def _tx() -> str:
    return "0x" + secrets.token_hex(32)


@app.post("/v1/events")
async def submit(request: Request):
    if state.fail_status:
        return JSONResponse({"type": "about:blank", "title": "refused", "status": state.fail_status,
                             "code": "VALIDATION_ERROR"}, status_code=state.fail_status)
    body = await request.json()
    results = []
    for ev in body["events"]:
        state.received.append(ev)
        eid, el = ev["event_id"], ev["election_id"]
        old = state.events.get(eid)
        if old is not None:
            results.append({"event_id": eid, "status": "DUPLICATE" if old["payload_hash"] == ev["payload_hash"]
                            else "CONFLICT"})
            continue
        voter = eid.startswith("evr_")
        if voter and el not in state.opened:
            results.append({"event_id": eid, "status": "RETRY_LATER"})
            continue
        if not voter:
            expected = state.last_seq.get(el, 0) + 1
            if ev["seq"] != expected:
                results.append({"event_id": eid, "status": "RETRY_LATER", "reject_code": "SEQUENCE_GAP"})
                continue
            state.last_seq[el] = ev["seq"]
        if ev["type"] in state.reject_types:
            state.events[eid] = ev
            results.append({"event_id": eid, "status": "REJECTED", "reject_code": "INVALID_STATE_TRANSITION",
                            "rejection_id": "rej_" + "0" * 26})
            continue
        state.block += 1
        state.events[eid] = dict(ev, anchor={"status": "ANCHORED", "anchor_id": "anc_" + "1" * 26,
                                             "mode": "batched" if voter else "immediate",
                                             "merkle_root": "0" * 64, "tx_hash": _tx(), "block_number": state.block})
        if ev["type"] == "ELECTION_OPENED":
            state.opened.add(el)
        res = {"event_id": eid, "status": "ACCEPTED", "anchor_mode": "batched" if voter else "immediate"}
        if not voter:
            res |= {"tx_hash": _tx(), "block_number": state.block}
        results.append(res)
    return {"results": results}


@app.get("/v1/events/{event_id}")
def get_event(event_id: str):
    ev = state.events.get(event_id)
    if ev is None:
        return JSONResponse({"type": "about:blank", "title": "not found", "status": 404, "code": "NOT_FOUND"},
                            status_code=404)
    return ev


@app.get("/v1/organizations")
def organizations():
    return {"items": [o | {"registered_by": "0x" + "00" * 20, "tx_hash": "0x" + "00" * 32, "block_number": 1}
                      for o in ORGS]}


@app.post("/v1/finding-records", status_code=201)
async def record_finding(request: Request):
    b = await request.json()
    fid = b["finding_id"]
    if fid in state.records:
        same = state.records[fid]["payload"]["finding_hash"] == b["finding_hash"]
        return JSONResponse({"event_id": state.records[fid]["event_id"]}, status_code=200 if same else 409)
    payload = {k: b[k] for k in ("finding_id", "rule_id", "result", "finding_checkpoint", "finding_hash", "signature")}
    payload["submitted_via"] = "GATEWAY"
    event_id = "evt_" + "".join(secrets.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(26))
    state.records[fid] = {"event_id": event_id, "election_id": b["election_id"], "type": "FINDING_RECORDED",
                          "source": "gateway", "payload": payload,
                          "payload_hash": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}
    return {"event_id": event_id}


@app.get("/v1/finding-records")
def finding_records(election_id: str, limit: int = 100, cursor: str | None = None):
    items = [{"finding_id": fid, "recorded": ev, "reviews": [],
              "contract_status": "NOT_REQUIRED" if ev["payload"]["result"] == "PASS" else "PENDING"}
             for fid, ev in state.records.items() if ev["election_id"] == election_id]
    return {"items": items, "next_cursor": None}


@app.get("/v1/health")
def health():
    return {"status": "ok"}
