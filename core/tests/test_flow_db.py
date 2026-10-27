"""Week 2 path against a real PostgreSQL and the fake Gateway: election → creation check → roster → freeze → links →
open → redeem → ballot → periodic checkpoint → views → close / CLOSE_FINAL → finding storage.

Needs TEST_DATABASE_URL (pv2_core on a database initialised with core/db/init); skipped otherwise. CI runs it in the
`db` job.
"""
import base64
import json
import os
import secrets
import time
from urllib.parse import urlparse

import nacl.public
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL not set")

if URL:
    from app import db, hashing, outbox
    from app.auth import hash_password
    from app.config import settings
    from app.gateway import GatewayClient, set_gateway
    from app.ids import ulid
    from app.main import app, scheduler_tick
    from app.timeutil import clock, iso, parse_iso
    from devtools import fake_gateway

RULE_KEY = "test-rule-key"
B = 60   # demo bucket and checkpoint interval


@pytest.fixture()
def env():
    settings.database_url = URL
    settings.run_workers = False
    settings.jwt_secret = "test-jwt-secret"
    settings.rule_key = RULE_KEY
    settings.agent_key = "test-agent-key"
    settings.creation_check_mode = "stub"
    db._engine = None
    fake_gateway.state = fake_gateway.State()
    set_gateway(GatewayClient(http=TestClient(fake_gateway.app)))
    outbox._backoff.clear()
    t0 = (int(time.time()) // 3600 + 1) * 3600          # an hour boundary in the future
    clock.frozen = t0
    username = "admin_" + secrets.token_hex(4)
    with db.get_engine().begin() as conn:
        conn.execute(text("INSERT INTO credential.staff_users (user_id, username, password_hash, org_id, role) "
                          "VALUES (:i, :u, :p, 'org_commission', 'admin')"),
                     {"i": ulid("usr"), "u": username, "p": hash_password("pw-123456")})
    client = TestClient(app)
    tok = client.post("/v1/auth/login", json={"username": username, "password": "pw-123456"}).json()["access_token"]
    yield {"client": client, "auth": {"Authorization": f"Bearer {tok}"}, "t0": t0}
    clock.frozen = None
    set_gateway(None)
    settings.database_url = ""
    db._engine = None


def deliver_until_idle(*eids):
    # only this test's elections: the database may be shared with a running stack
    for _ in range(20):
        outbox._backoff.clear()
        outbox.deliver_all(list(eids))


def outbox_rows(eid):
    with db.get_engine().connect() as conn:
        return [dict(r) for r in conn.execute(text("SELECT event_id, kind, seq, status, event FROM credential.outbox "
                                                   "WHERE election_id = :e"), {"e": eid}).mappings()]


def test_week2_path(env):
    c, auth, t0 = env["client"], env["auth"], env["t0"]
    start, end = t0 + 10 * B, t0 + 20 * B      # 10-minute window, 60 s buckets → 100 voters needed (D-10)

    # ---- create: DRAFT, creation check pending, nothing but ELECTION_CREATED can be delivered ----
    r = c.post("/v1/elections", headers=auth, json={
        "title": "Week 2 test", "window_start": iso(start), "window_end": iso(end),
        "time_bucket_seconds": B, "checkpoint_interval_seconds": B,
        "candidates": [{"name": "Kim"}, {"name": "Lee"}],
        "org_ids": ["org_commission", "org_neutral", "org_observer"], "approval_threshold": 2})
    assert r.status_code == 201, r.text
    e = r.json()
    eid = e["election_id"]
    assert e["status"] == "DRAFT" and e["creation_check"] == "PENDING" and e["operator_org"] == "org_commission"

    voters = [{"external_ref": f"s{i:03d}", "name": f"Voter {i}"} for i in range(100)]
    assert c.put(f"/v1/elections/{eid}/roster", headers=auth, json={"voters": voters}).status_code == 200
    assert c.post(f"/v1/elections/{eid}/roster:freeze", headers=auth).status_code == 409   # check not passed yet

    clock.frozen = t0 + B        # ELECTION_CREATED's bucket has ended
    deliver_until_idle(eid)
    e = c.get(f"/v1/elections/{eid}", headers=auth).json()
    assert e["creation_check"] == "PASSED" and e["transition"]["ledger_status"] == "ACCEPTED"

    # ---- freeze → checkpoint 0 committed (STATE_CHANGE); links ----
    r = c.post(f"/v1/elections/{eid}/roster:freeze", headers=auth)
    assert r.status_code == 202 and r.json()["status"] == "ROSTER_FROZEN" and r.json()["open_checkpoint"] == 1
    assert c.put(f"/v1/elections/{eid}/roster", headers=auth, json={"voters": voters}).status_code == 409

    r = c.post(f"/v1/elections/{eid}/tokens:issue", headers={**auth, "Idempotency-Key": "issue-0001"},
               json={"delivery": "CSV"})
    assert r.status_code == 200
    lines = r.text.strip().splitlines()
    assert lines[0] == "external_ref,name,link" and len(lines) == 101
    again = c.post(f"/v1/elections/{eid}/tokens:issue", headers={**auth, "Idempotency-Key": "issue-0001"},
                   json={"delivery": "CSV"})
    assert again.text == r.text                                   # lost-response retry: same CSV
    tokens = [ln.rsplit("#t=", 1)[1] for ln in lines[1:]]
    assert c.post(f"/v1/elections/{eid}/tokens:issue", headers=auth, json={"delivery": "CSV"}).text == ""

    # ---- open at window_start (permissive: OPEN only after ACCEPTED) ----
    clock.frozen = start
    scheduler_tick([eid])
    assert c.get(f"/v1/public/elections/{eid}").json()["status"] == "ROSTER_FROZEN"
    deliver_until_idle(eid)
    pub = c.get(f"/v1/public/elections/{eid}").json()
    assert pub["status"] == "OPEN"

    # ---- vote ----
    clock.frozen = start + 5
    cand = pub["candidates"][0]["candidate_id"]
    sealed = nacl.public.SealedBox(nacl.public.PublicKey(base64.b64decode(pub["public_key"]))).encrypt(
        json.dumps({"candidate_id": cand}).encode())
    credential = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
    nullifier = hashing.H(credential)
    r = c.post("/v1/credentials:redeem", json={"election_id": eid, "token": tokens[0], "nullifier_hash": nullifier})
    assert r.status_code == 200, r.text
    r = c.post("/v1/credentials:redeem", json={"election_id": eid, "token": tokens[0], "nullifier_hash": nullifier})
    assert r.status_code == 409 and r.json()["code"] == "TOKEN_ALREADY_USED"
    bad = c.post("/v1/credentials:redeem", json={"election_id": eid, "token": "A" * 22, "nullifier_hash": "0" * 64})
    assert bad.status_code == 404 and bad.json()["code"] == "TOKEN_INVALID"

    ballot = {"election_id": eid, "credential": credential, "sealed_ballot": base64.b64encode(sealed).decode()}
    r = c.post("/v1/ballots", json=ballot)
    assert r.status_code == 201, r.text
    receipt = r.json()["receipt_hash"]
    assert receipt == hashing.receipt_hash(eid, nullifier, hashing.H(sealed))     # voter can compute it locally
    assert c.post("/v1/ballots", json=ballot).status_code == 200                  # identical retry
    other = dict(ballot, sealed_ballot=base64.b64encode(b"x" * 80).decode())
    assert c.post("/v1/ballots", json=other).json()["code"] == "CREDENTIAL_ALREADY_USED"
    stranger = dict(ballot, credential="B" * 22)
    assert c.post("/v1/ballots", json=stranger).json()["code"] == "CREDENTIAL_UNKNOWN"

    # ---- periodic checkpoint at start + B; delivery; snapshot hash from the view equals the committed one ----
    clock.frozen = start + B
    # a voter request exactly at the boundary T, before the scheduler ran: the request itself commits the PERIODIC
    # checkpoint first, then gets checkpoint k+1 and the bucket that starts at T (boundary serialization)
    cred2 = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
    assert c.post("/v1/credentials:redeem", json={"election_id": eid, "token": tokens[2],
                                                  "nullifier_hash": hashing.H(cred2)}).status_code == 200
    used2 = [r["event"] for r in outbox_rows(eid) if r["event"]["type"] == "TOKEN_USED"
             and r["event"]["occurred_at"] == iso(start + B)]
    assert len(used2) == 1 and used2[0]["checkpoint"] == 3
    scheduler_tick([eid])
    deliver_until_idle(eid)
    rk = {"X-Service-Key": RULE_KEY}
    cps = c.get("/internal/v1/checkpoints", params={"election_id": eid}, headers=rk).json()
    reasons = [(x["checkpoint"], x["reason"], x["ledger_status"]) for x in cps["items"]]
    assert reasons == [(0, "STATE_CHANGE", "ACCEPTED"), (1, "STATE_CHANGE", "ACCEPTED"), (2, "PERIODIC", "ACCEPTED")]
    page = c.get("/internal/v1/views/ballot_receipts", params={"election_id": eid, "checkpoint": 2}, headers=rk).json()
    assert page["total_rows"] == 1 and page["rows"][0]["receipt_hash"] == receipt
    committed = next(r["event"] for r in outbox_rows(eid) if r["event"]["type"] == "CHECKPOINT_COMMITTED"
                     and r["event"]["checkpoint"] == 2)
    by_table = {t["table"]: t for t in committed["payload"]["tables"]}
    assert by_table["ballot_receipts"]["snapshot_hash"] == page["snapshot_hash"]
    assert committed["payload"]["voter_events"] == {"TOKEN_USED": 1, "BALLOT_RECEIVED": 1}
    # early freeze, roster PUT after freeze, used token, bad token, two bad ballots
    assert committed["payload"]["counts"]["rejected_attempts"] == 6
    cfg = c.get("/internal/v1/views/election_config", params={"election_id": eid}, headers=rk).json()
    assert cfg["snapshot_hash"] is None and cfg["rows"][0]["private_key"] is None    # not before TALLY
    assert c.get("/internal/v1/views/roster", params={"election_id": eid}).status_code == 403   # no key

    assert c.get(f"/v1/public/receipts/{receipt}").json()["status"] == "ANCHORED"

    # ---- delivery order: core seq gap-free; inside a unit voter events precede system events ----
    sent = fake_gateway.state.received
    seqs = [ev["seq"] for ev in sent if ev["election_id"] == eid and "seq" in ev]
    assert sorted(set(seqs)) == list(range(1, max(seqs) + 1))
    first_voter = next(i for i, ev in enumerate(sent) if ev["event_id"].startswith("evr_"))
    periodic = next(i for i, ev in enumerate(sent) if ev["type"] == "CHECKPOINT_COMMITTED"
                    and ev["payload"]["reason"] == "PERIODIC")
    assert first_voter < periodic

    # ---- close at window_end: CLOSED (strict), STATE_CHANGE + CLOSE_FINAL; late redeem refused ----
    clock.frozen = end
    r = c.post("/v1/credentials:redeem", json={"election_id": eid, "token": tokens[1], "nullifier_hash": "1" * 64})
    assert r.status_code == 409 and r.json()["code"] == "ELECTION_NOT_OPEN"
    deliver_until_idle(eid)
    items = c.get("/internal/v1/elections", headers=rk).json()["items"]
    mine = next(x for x in items if x["election_id"] == eid)
    assert mine["status"] == "CLOSED" and mine["close_final_checkpoint"] == mine["last_committed_checkpoint"]
    assert all(r["status"] == "ACCEPTED" for r in outbox_rows(eid))
    # every event Core sent is a valid LedgerEventSubmission (contracts/ledger-events.schema.json)
    from app import schemas
    for row in outbox_rows(eid):
        assert schemas.errors("ledger-events.schema.json", "LedgerEventSubmission", row["event"]) == [], row["event"]
    types = [r["event"]["type"] for r in sorted(outbox_rows(eid), key=lambda r: r["seq"] or 0) if r["seq"]]
    # freeze → STATE_CHANGE; open → STATE_CHANGE; 9 PERIODIC (start+60 … start+540); close → STATE_CHANGE, CLOSE_FINAL
    assert types == (["ELECTION_CREATED", "ROSTER_FROZEN", "CHECKPOINT_COMMITTED", "TOKEN_BATCH_ISSUED",
                      "ELECTION_OPENED", "CHECKPOINT_COMMITTED"] + ["CHECKPOINT_COMMITTED"] * 9
                     + ["ELECTION_CLOSED", "CHECKPOINT_COMMITTED", "CHECKPOINT_COMMITTED"])
    periodic = [r["event"]["occurred_at"] for r in outbox_rows(eid) if r["event"]["type"] == "CHECKPOINT_COMMITTED"
                and r["event"]["payload"]["reason"] == "PERIODIC"]
    assert sorted(periodic) == [iso(start + i * B) for i in range(1, 10)]     # logical boundary times (R5 cadence)

    # ---- finding storage: needs the FINDING_RECORDED first ----
    finding = {
        "finding_id": ulid("fnd"), "schema_version": "1", "rule_id": "R1", "rule_version": "0.1.0",
        "election_id": eid, "result": "PASS", "trigger": "SCHEDULED", "checked_at": iso(end + 30),
        "checkpoint": 2, "data_as_of": {"ledger_last_seq": 1, "ledger_last_block": 1,
                                        "checkpoint_event_id": committed["event_id"]},
        "observed": {"accepted_duplicate_tokens": 0, "accepted_duplicate_nullifiers": 0, "unknown_tokens": 0,
                     "unknown_nullifiers": 0, "used_then_revoked": 0, "refused_duplicates": 1},
        "expected": "no accepted duplicates", "summary": "No accepted duplicates.", "evidence_refs": [],
    }
    assert c.post("/internal/v1/findings", json=finding, headers=rk).status_code == 503     # not recorded yet
    fg = TestClient(fake_gateway.app)
    fg.post("/v1/finding-records", json={
        "election_id": eid, "finding_id": finding["finding_id"], "rule_id": "R1", "result": "PASS",
        "finding_checkpoint": 2, "finding_hash": hashing.Hc(finding),
        "signature": {"scheme": "eip191-secp256k1", "signer": "0x" + "c3" * 20, "value": "0x" + "00" * 65}})
    assert c.post("/internal/v1/findings", json=finding, headers=rk).status_code == 201
    assert c.post("/internal/v1/findings", json=finding, headers=rk).status_code == 200
    changed = dict(finding, summary="Changed.")
    assert c.post("/internal/v1/findings", json=changed, headers=rk).status_code == 409
    stored = c.get(f"/internal/v1/findings/{finding['finding_id']}", headers=rk).json()
    assert stored["review"]["status"] == "NOT_REQUIRED" and stored["recorded_event_id"].startswith("evt_")


def test_ledger_rejection_of_election_created_allows_delete(env):
    c, auth, t0 = env["client"], env["auth"], env["t0"]
    fake_gateway.state.reject_types.add("ELECTION_CREATED")
    r = c.post("/v1/elections", headers=auth, json={
        "title": "Rejected", "window_start": iso(t0 + 600), "window_end": iso(t0 + 1200),
        "time_bucket_seconds": B, "checkpoint_interval_seconds": B, "candidates": [{"name": "A"}],
        "org_ids": ["org_commission", "org_neutral", "org_observer"], "approval_threshold": 2})
    eid = r.json()["election_id"]
    assert c.post(f"/v1/elections/{eid}:delete", headers=auth).status_code == 409     # still pending
    clock.frozen = t0 + B
    deliver_until_idle(eid)
    e = c.get(f"/v1/elections/{eid}", headers=auth).json()
    assert e["transition"]["ledger_status"] == "REJECTED"
    alerts = c.get(f"/v1/elections/{eid}/audit-alerts", headers=auth).json()["items"]
    assert [a["kind"] for a in alerts] == ["TRANSITION_REJECTED"]
    assert c.post(f"/v1/elections/{eid}:delete", headers=auth).status_code == 204
    assert c.get(f"/v1/elections/{eid}", headers=auth).status_code == 404


def test_bucket_too_small_and_validation(env):
    c, auth, t0 = env["client"], env["auth"], env["t0"]
    base = {"title": "Small", "window_start": iso(t0 + 600), "window_end": iso(t0 + 1200),
            "time_bucket_seconds": B, "checkpoint_interval_seconds": B, "candidates": [{"name": "A"}],
            "org_ids": ["org_commission", "org_neutral", "org_observer"], "approval_threshold": 2}
    assert c.post("/v1/elections", headers=auth, json=dict(base, window_start=iso(t0 + 601))).status_code == 422
    assert c.post("/v1/elections", headers=auth, json=dict(base, approval_threshold=3)).status_code == 422
    assert c.post("/v1/elections", headers=auth,
                  json=dict(base, org_ids=["org_commission", "org_neutral", "org_unknown"])).json()["code"] \
        == "ORG_NOT_REGISTERED"
    eid = c.post("/v1/elections", headers=auth, json=base).json()["election_id"]
    clock.frozen = t0 + B
    deliver_until_idle(eid)
    c.put(f"/v1/elections/{eid}/roster", headers=auth,
          json={"voters": [{"external_ref": f"x{i}", "name": "n"} for i in range(20)]})
    r = c.post(f"/v1/elections/{eid}/roster:freeze", headers=auth)
    assert r.status_code == 422 and r.json()["code"] == "BUCKET_TOO_SMALL"


def _create(c, auth, t0, title="Idem", key=None):
    headers = dict(auth, **({"Idempotency-Key": key} if key else {}))
    return c.post("/v1/elections", headers=headers, json={
        "title": title, "window_start": iso(t0 + 600), "window_end": iso(t0 + 1200),
        "time_bucket_seconds": B, "checkpoint_interval_seconds": B, "candidates": [{"name": "A"}],
        "org_ids": ["org_commission", "org_neutral", "org_observer"], "approval_threshold": 2})


def test_idempotency_keys(env):
    c, auth, t0 = env["client"], env["auth"], env["t0"]
    key = "create-" + secrets.token_hex(4)
    first = _create(c, auth, t0, key=key)
    again = _create(c, auth, t0, key=key)
    assert first.status_code == 201 and again.status_code == 201
    assert again.json()["election_id"] == first.json()["election_id"]          # no second election
    assert _create(c, auth, t0, title="Other", key=key).status_code == 409      # same key, different body

    eid = first.json()["election_id"]
    clock.frozen = t0 + B
    deliver_until_idle(eid)
    c.put(f"/v1/elections/{eid}/roster", headers=auth,
          json={"voters": [{"external_ref": f"v{i}", "name": "n"} for i in range(100)]})
    assert c.post(f"/v1/elections/{eid}/roster:freeze", headers=auth).status_code == 202
    ikey = {**auth, "Idempotency-Key": "issue-" + secrets.token_hex(4)}
    csv1 = c.post(f"/v1/elections/{eid}/tokens:issue", headers=ikey, json={"delivery": "CSV"}).text
    assert len(csv1.splitlines()) == 101
    assert c.post(f"/v1/elections/{eid}/tokens:issue", headers=ikey, json={"delivery": "CSV"}).text == csv1
    from app import elections as el
    el.issue_cache._items.clear()                       # CSV wiped (15 min passed, or Core restarted)
    late = c.post(f"/v1/elections/{eid}/tokens:issue", headers=ikey, json={"delivery": "CSV"})
    assert late.status_code == 409                      # never an empty 200 that hides the lost links


def test_gateway_4xx_raises_alert(env):
    c, auth, t0 = env["client"], env["auth"], env["t0"]
    eid = _create(c, auth, t0, title="4xx").json()["election_id"]
    fake_gateway.state.fail_status = 400
    clock.frozen = t0 + B
    deliver_until_idle(eid)
    kinds = [a["kind"] for a in c.get(f"/v1/elections/{eid}/audit-alerts", headers=auth).json()["items"]]
    assert kinds == ["LEDGER_UNAVAILABLE"]
    assert c.get(f"/v1/elections/{eid}", headers=auth).json()["creation_check"] == "PENDING"


def test_node_mode_keeps_creation_check_pending(env):
    c, auth, t0 = env["client"], env["auth"], env["t0"]
    settings.creation_check_mode = "node"
    eid = _create(c, auth, t0, title="Node").json()["election_id"]
    clock.frozen = t0 + B
    deliver_until_idle(eid)
    scheduler_tick([eid])
    e = c.get(f"/v1/elections/{eid}", headers=auth).json()
    assert e["transition"]["ledger_status"] == "ACCEPTED" and e["creation_check"] == "PENDING"
    assert c.post(f"/v1/elections/{eid}/roster:freeze", headers=auth).status_code == 409
