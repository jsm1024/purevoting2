"""T02, T04, T05 and T08 variants (docs/test-plan.md): the T01 flow (T01/setup.py) plus one fault, judged against the
variant's expected.json (Harits, tests/scenarios/LABELS_T02_T04.md and LABELS_T05_T08.md). Each variant folder's
setup.py calls main() here. How to run: SETUP_T02_T04.md, SETUP_T05_T08.md.

  T02            after the ballots, inside the window: the second redeem of a used link, 409 TOKEN_ALREADY_USED
  T04-core       before window_start: one redeem, 409 ELECTION_NOT_OPEN
  T04-lastbucket the last voter redeems and votes in the window's last bucket (accepted, 201)
  T04-injected   after the ballots' checkpoint is committed, one TOKEN_USED with a bucketed time before window_start
                 written into Core's outbox (Core's open checkpoint, read in the same statement); the Gateway must
                 reject it ELECTION_NOT_OPEN

  T05-api     after the freeze, PUT the roster again: Core must answer 409 and change nothing
  T05-db-add  after the ballots' checkpoint is committed, INSERT one ACTIVE roster row in the database with
              added_checkpoint = Core's open checkpoint (read in the same statement)
  T08a        after that checkpoint, change one ballot_receipts row's receipt_hash
  T08b        ... change one byte of sealed_ballot, ballot_hash kept
  T08c        ... change one byte of sealed_ballot and set ballot_hash = H(new bytes)

The database edits run as the postgres superuser through `$COMPOSE exec -T db psql` (COMPOSE as in tools/trustees.sh).
The edited row must already be in a committed checkpoint and the judged checkpoint is the one that commits the edit
(Core's open checkpoint at the time of the edit); the script stops (NOT COMPLETED) if either does not hold.
Nothing secret is printed: the SQL holds only the election id, and psql returns checkpoint numbers.
"""
import importlib.util
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("t01_setup", HERE / "T01" / "setup.py")
t01 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(t01)

ELECTION_ID = re.compile(r"elc_[0-9A-HJKMNP-TV-Z]{26}")   # core/app/models.py ELC
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# one ballot_receipts row of the election, picked by its key; SET clauses use the row's old values
ROW_EDITS = {
    "T08a": "receipt_hash = encode(sha256(convert_to(b.receipt_hash || 'T08a', 'UTF8')), 'hex')",
    "T08b": "sealed_ballot = set_byte(b.sealed_ballot, 0, get_byte(b.sealed_ballot, 0) # 1)",
    "T08c": "sealed_ballot = set_byte(b.sealed_ballot, 0, get_byte(b.sealed_ballot, 0) # 1), "
            "ballot_hash = encode(sha256(set_byte(b.sealed_ballot, 0, get_byte(b.sealed_ballot, 0) # 1)), 'hex')",
}


def row_edit_sql(variant: str, eid: str) -> str:
    """Returns one line "open_checkpoint|received_checkpoint" when exactly one row was changed."""
    return (
        "WITH target AS (SELECT nullifier_hash FROM ballot.ballot_receipts "
        f"WHERE election_id = '{eid}' ORDER BY nullifier_hash LIMIT 1), "
        f"upd AS (UPDATE ballot.ballot_receipts b SET {ROW_EDITS[variant]} FROM target t "
        f"WHERE b.election_id = '{eid}' AND b.nullifier_hash = t.nullifier_hash RETURNING b.received_checkpoint) "
        f"SELECT (SELECT open_checkpoint FROM credential.elections WHERE election_id = '{eid}'), "
        "received_checkpoint FROM upd;"
    )


def roster_insert_sql(eid: str, voter_key: str, ref: str) -> str:
    """Returns one line: the added_checkpoint, which is Core's open checkpoint when the row is inserted. FOR SHARE
    waits for a checkpoint commit in progress (Core holds the election row FOR UPDATE while it commits)."""
    return (
        "INSERT INTO credential.roster (election_id, voter_key, name, email, external_ref, added_checkpoint) "
        f"SELECT '{eid}', '{voter_key}', 'injected voter', NULL, '{ref}', open_checkpoint "
        f"FROM credential.elections WHERE election_id = '{eid}' FOR SHARE RETURNING added_checkpoint;"
    )


def psql(sql: str) -> list[str]:
    compose = shlex.split(os.environ.get("COMPOSE", "docker compose"))
    cmd = compose + ["exec", "-T", "db", "sh", "-c",
                     'psql -X -q -t -A -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB"']
    try:
        r = subprocess.run(cmd, input=sql, capture_output=True, text=True, timeout=60, cwd=HERE.parents[1])
    except (OSError, subprocess.SubprocessError) as exc:
        raise t01.Stop(f"database edit not run: {type(exc).__name__}") from exc
    if r.returncode != 0:
        raise t01.Stop(f"database edit failed (psql exit {r.returncode}): {r.stderr.strip()[:200]}")
    return [ln for ln in r.stdout.splitlines() if ln.strip()]


def committed(ctx) -> int:
    return ctx["staff_election"]()["counters"]["as_of_checkpoint"]


def check_election_id(eid: str) -> str:
    if not ELECTION_ID.fullmatch(eid):
        raise t01.Stop("unexpected election id format; not put into SQL")
    return eid


def roster_put_after_freeze(ctx) -> None:
    """T05-api: the roster PUT after the freeze is refused (409) and the roster is unchanged."""
    c, auth, eid, rec = ctx["client"], ctx["auth"], ctx["election_id"], ctx["rec"]
    before = ctx["staff_election"]().get("roster_hash")
    r = c.put(f"/v1/elections/{eid}/roster", headers=auth,
              json={"voters": [{"external_ref": "T05-api-extra", "name": "added after freeze"}]})
    rec["checks"]["roster_put_after_freeze"] = {"status": r.status_code,
                                                "code": (r.json().get("code") if r.status_code >= 400 else None)}
    n = len(t01.expect(c.post(f"/v1/elections/{eid}/roster:read", headers=auth), 200).json()["voters"])
    same = before is not None and ctx["staff_election"]().get("roster_hash") == before
    rec["checks"]["roster_size_after_put"], rec["checks"]["roster_hash_unchanged"] = n, same
    t01.log(f"roster PUT after freeze: HTTP {r.status_code}; roster has {n} voters, roster_hash unchanged: {same}")
    if r.status_code != 409 or n != ctx["voters"] or not same:
        raise t01.Failed(f"roster PUT after freeze: HTTP {r.status_code}, {n} voters (expected 409, {ctx['voters']})")


def roster_insert(ctx, k: int) -> int:
    """T05-db-add: one ACTIVE row as of Core's open checkpoint, which must not be committed yet."""
    eid, rec = check_election_id(ctx["election_id"]), ctx["rec"]
    voter_key = "vtr_" + "".join(secrets.choice(CROCKFORD) for _ in range(26))
    out = psql(roster_insert_sql(eid, voter_key, "T05-injected"))
    if len(out) != 1:
        raise t01.Stop(f"roster insert returned {len(out)} rows")
    added = int(out[0])
    done = committed(ctx)
    rec["injection"] = {"kind": "roster row inserted in the database", "added_checkpoint": added,
                        "committed_at_insert": done}
    t01.log(f"inserted one ACTIVE roster row in the database, added_checkpoint {added} (committed: {done})")
    if added <= done:   # LABELS_T05_T08.md: an already committed value is the variant T05-db-add-old
        raise t01.Stop(f"added_checkpoint {added} is already committed (T05-db-add-old, not this label)")
    return added


def row_edit(variant: str):
    def hook(ctx, k: int) -> int:
        """T08a/b/c: edit one ballot row that a committed checkpoint already contains."""
        eid, rec = check_election_id(ctx["election_id"]), ctx["rec"]
        done = committed(ctx)
        out = psql(row_edit_sql(variant, eid))
        if len(out) != 1:
            raise t01.Stop(f"ballot row edit changed {len(out)} rows (expected 1)")
        open_k, received = (int(x) for x in out[0].split("|"))
        rec["injection"] = {"kind": f"ballot_receipts row edited ({variant})", "row_received_checkpoint": received,
                            "open_checkpoint_at_edit": open_k, "committed_before_edit": done}
        t01.log(f"edited one ballot_receipts row ({variant}); row in checkpoint {received}, "
                f"committed {done}, judged checkpoint {open_k}")
        if received > done:   # LABELS_T05_T08.md: tampered before its checkpoint = a different scenario
            raise t01.Stop(f"the edited row's checkpoint {received} was not committed yet")
        return open_k
    return hook


def _redeem(ctx, token: str):
    c, eid = ctx["client"], ctx["election_id"]
    r = c.post("/v1/credentials:redeem", json={"election_id": eid, "token": token,
                                                "nullifier_hash": t01.H(secrets.token_urlsafe(16))})
    return r.status_code, (r.json().get("code") if r.status_code >= 400 else None)


def duplicate_redeem(ctx, voted: list[int]) -> None:
    """T02 (LABELS_T02_T04.md): the second redeem of a link that was already used, inside the window and before the
    judged checkpoint is read (so its rejected_attempts row has checkpoint <= C): 409 TOKEN_ALREADY_USED."""
    if time.time() >= ctx["window_end"]:
        raise t01.Stop("the window ended before the second redeem")
    status, code = _redeem(ctx, ctx["tokens"][voted[0]])
    ctx["rec"]["checks"]["second_redeem"] = {"status": status, "code": code}
    t01.log(f"second redeem of a used link: HTTP {status} {code}")
    if (status, code) != (409, "TOKEN_ALREADY_USED"):
        raise t01.Failed(f"second redeem: HTTP {status} {code} (expected 409 TOKEN_ALREADY_USED)")


def redeem_before_start(ctx) -> None:
    """T04-core: one redeem before window_start (a redeem, never a ballot: a ballot gets CREDENTIAL_UNKNOWN first):
    409 ELECTION_NOT_OPEN, recorded at Core's open checkpoint (<= C)."""
    status, code = _redeem(ctx, ctx["tokens"][-1])
    ctx["rec"]["checks"]["redeem_before_start"] = {"status": status, "code": code,
                                                   "seconds_before_start": round(ctx["window_start"] - time.time())}
    t01.log(f"redeem before window_start: HTTP {status} {code}")
    if (status, code) != (409, "ELECTION_NOT_OPEN"):
        raise t01.Failed(f"redeem before start: HTTP {status} {code} (expected 409 ELECTION_NOT_OPEN)")


def wait_last_bucket(ctx, n: int) -> None:
    """T04-lastbucket: the last voter redeems and votes inside the window's last bucket
    (occurred_at + time_bucket_seconds = effective_end)."""
    if n != ctx["rec"]["parameters"]["votes"] - 1:
        return
    last = ctx["window_end"] - ctx["bucket"]
    wait = last + 2 - time.time()
    if wait < 0:
        raise t01.Stop("the earlier ballots ran into the last bucket; use a longer window")
    t01.log(f"waiting {int(wait)} s for the last bucket")
    time.sleep(wait)


def check_last_bucket(ctx, voted: list[int]) -> None:
    """T04-lastbucket: exactly one BALLOT_RECEIVED of the election is in the last bucket (outbox bucket_start)."""
    eid = check_election_id(ctx["election_id"])
    if time.time() >= ctx["window_end"]:
        raise t01.Stop("the last ballot finished after window_end")
    out = psql(f"SELECT count(*) FROM credential.outbox WHERE election_id = '{eid}' AND event->>'type' = "
               f"'BALLOT_RECEIVED' AND bucket_start = to_timestamp({ctx['window_end'] - ctx['bucket']});")
    n = int(out[0])
    ctx["rec"]["checks"]["ballots_in_last_bucket"] = n
    t01.log(f"BALLOT_RECEIVED in the last bucket: {n}")
    if n != 1:
        raise t01.Stop(f"{n} ballots in the last bucket (expected 1)")


def inject_outside_window(ctx, k: int) -> int:
    """T04-injected: one TOKEN_USED written straight into Core's outbox, bypassing Core: bucketed time one bucket
    before window_start, valid payload_hash and key field, checkpoint = Core's open checkpoint read in the same
    statement (not committed yet, <= CLOSE_FINAL). The Gateway must reject it ELECTION_NOT_OPEN; Core keeps no row."""
    from app import hashing                  # core/app, on sys.path through T01/setup.py
    from app.ids import random_id
    eid, rec = check_election_id(ctx["election_id"]), ctx["rec"]
    t = ctx["window_start"] - ctx["bucket"]
    payload = {"token_hash": t01.H("T04-injected " + secrets.token_hex(16))}
    event = {"event_id": random_id("evr"), "schema_version": "1", "election_id": eid, "type": "TOKEN_USED",
             "source": "core", "checkpoint": 0, "occurred_at": t01.iso(t), "time_precision": "bucketed",
             "time_bucket_seconds": ctx["bucket"], "actor": {"kind": "voter_anonymous"},
             "payload": payload, "payload_hash": hashing.Hc(payload)}
    body = json.dumps(event, separators=(",", ":"))
    if not re.fullmatch(r"[A-Za-z0-9_:,{}\"\-]+", body):
        raise t01.Stop("unexpected characters in the injected event; not put into SQL")
    done = committed(ctx)
    out = psql(
        "INSERT INTO credential.outbox (event_id, election_id, kind, seq, bucket_start, event, payload_hash) "
        f"SELECT '{event['event_id']}', '{eid}', 'voter', NULL, to_timestamp({t}), "
        f"jsonb_set(CAST('{body}' AS jsonb), '{{checkpoint}}', to_jsonb(open_checkpoint)), '{event['payload_hash']}' "
        f"FROM credential.elections WHERE election_id = '{eid}' FOR SHARE RETURNING (event->>'checkpoint')::int;")
    if len(out) != 1:
        raise t01.Stop(f"outbox insert returned {len(out)} rows")
    judged = int(out[0])
    rec["injection"] = {"kind": "TOKEN_USED outside the window written into the outbox",
                        "event_checkpoint": judged, "committed_at_insert": done,
                        "occurred_at_before_start_s": ctx["window_start"] - t}
    t01.log(f"injected one TOKEN_USED (occurred_at one bucket before window_start) at checkpoint {judged} "
            f"(committed: {done})")
    if judged <= done:
        raise t01.Stop(f"the injected event's checkpoint {judged} is already committed")

    def outcome():
        row = psql(f"SELECT status || '|' || coalesce(reject_code, '') FROM credential.outbox "
                   f"WHERE event_id = '{event['event_id']}';")
        return bool(row) and not row[0].startswith("PENDING") and row[0]
    status, code = t01.poll(outcome, 120, "the Gateway's outcome for the injected event").split("|")
    rec["injection"]["gateway_outcome"] = {"status": status, "reject_code": code or None}
    t01.log(f"Gateway outcome for the injected event: {status} {code}")
    if (status, code) != ("REJECTED", "ELECTION_NOT_OPEN"):
        raise t01.Stop(f"injected event {status} {code} (the label needs REJECTED ELECTION_NOT_OPEN)")
    return judged


VARIANTS = {
    "T02": {"after_ballots": duplicate_redeem},
    "T04-core": {"before_open": redeem_before_start},
    "T04-lastbucket": {"before_ballot": wait_last_bucket, "after_ballots": check_last_bucket},
    "T04-injected": {"after_commit": inject_outside_window},
    "T05-api": {"after_freeze": roster_put_after_freeze},
    "T05-db-add": {"after_commit": roster_insert},
    "T08a": {"after_commit": row_edit("T08a")},
    "T08b": {"after_commit": row_edit("T08b")},
    "T08c": {"after_commit": row_edit("T08c")},
}


def main(variant: str, argv=None) -> int:
    return t01.main(argv, scenario=variant, folder=HERE / variant, hooks=VARIANTS[variant])


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in VARIANTS:
        sys.exit(f"usage: {sys.argv[0]} {{{','.join(VARIANTS)}}} [T01 options]")
    sys.exit(main(sys.argv[1], sys.argv[2:]))
