"""T15 variants (docs/test-plan.md, labels: Harits, LABELS_T15.md): the T01 flow (T01/setup.py), then the election
closes, the three organizations send honest decryption shares, the admin runs the tally, and the TALLY_PUBLISHED
event is changed in Core's outbox before it is delivered. Each variant folder's setup.py calls main() here. How to
run: SETUP_T15.md.

  T15a-results    ballot_count = N - 1 and one vote fewer for a candidate that has one; root and shares honest
  T15a-aggregate  as T15a-results, with the results = the decryption of the aggregate of N - 1 ballots, and the three
                  stored shares replaced by shares over that aggregate (before the TALLY checkpoint is committed)
  T15b            one vote moved from a candidate that has one to another; ballot_count unchanged
  T15c            ballot_set_root over the N accepted ballot_hashes plus one extra 32-byte value; nothing else
  T15d            final_checkpoint = F - 1 (the contract must refuse publishTally; judged at F)

Every change recomputes result_hash = Hc(result) and payload_hash = Hc(payload), otherwise the Gateway refuses the
event with VALIDATION_ERROR before the contract sees it. Core releases a system event once its time bucket has ended,
so the tally is run early in a bucket and the change is made at once; the script stops (NOT COMPLETED) if the event
has already left. The organizations' secret files (T15_TRUSTEE_DIR, <org_id>.secret.json) are read here and never
printed; the run record holds checkpoint numbers, counts and the Gateway outcome only.
"""
import base64
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

from tamper import HERE, check_election_id, psql, t01

from app import elgamal, hashing   # core/app, on sys.path through T01/setup.py

SAFE_JSON = re.compile(r'[A-Za-z0-9_:,{}\[\]"\-]+')
EVENT_ID = re.compile(r"evt_[0-9A-HJKMNP-TV-Z]{26}")


def _ledger(path: str) -> list[dict]:
    """GET on the Gateway with the read-only key (T15_GATEWAY_URL, T15_AUDITOR_KEY): the items of one page."""
    url, key = os.environ.get("T15_GATEWAY_URL"), os.environ.get("T15_AUDITOR_KEY")
    if not (url and key):
        raise t01.Stop("set T15_GATEWAY_URL and T15_AUDITOR_KEY (the Gateway's read-only key) to check the ledger")
    r = t01.httpx.get(url.rstrip("/") + path, headers={"X-Service-Key": key}, timeout=30)
    if r.status_code != 200:
        raise t01.Stop(f"Gateway {path.split('?')[0]}: HTTP {r.status_code}")
    return r.json()["items"]


def _payload_of(result: dict) -> dict:
    """core/app/tally.py count(): the payload is the result without election_id, plus result_hash = Hc(result)."""
    return {k: v for k, v in result.items() if k != "election_id"} | {"result_hash": hashing.Hc(result)}


def _secrets(orgs: list[str]) -> dict[str, int]:
    folder = os.environ.get("T15_TRUSTEE_DIR")
    if not folder:
        raise t01.Stop("set T15_TRUSTEE_DIR (the folder with <org_id>.secret.json of every organization)")
    out = {}
    for org in orgs:
        try:
            d = json.loads((Path(folder) / f"{org}.secret.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise t01.Stop(f"{org}: secret file not readable ({type(exc).__name__})") from None
        x = int.from_bytes(bytes.fromhex(d["secret"]), "little")
        if d.get("org_id") != org or elgamal.base(x).hex() != d["record"]["public_key"]:
            raise t01.Stop(f"{org}: the secret file does not match its own key record")
        out[org] = x
    return out


def _ballot_cts(inp: dict) -> list[tuple[str, list]]:
    """(ballot_hash, ciphertexts) of every listed ballot whose proofs verify, sorted by ballot_hash."""
    Y, eid, n = bytes.fromhex(inp["public_key"]), inp["election_id"], len(inp["candidate_ids"])
    out = []
    for b in inp["ballots"]:
        if b["sealed_ballot"] is None:
            raise t01.Stop("Core cannot show a listed ballot (the variant needs every ballot)")
        cts = elgamal.verify_ballot(base64.b64decode(b["sealed_ballot"]), Y, eid, b["nullifier_hash"], n)
        if cts is None:
            raise t01.Stop("a listed ballot does not verify (the variant needs N valid ballots)")
        out.append((b["ballot_hash"], cts))
    return sorted(out, key=lambda x: x[0])


def _agg_json(agg) -> list[dict]:
    return [{"a": a.hex(), "b": b.hex()} for a, b in agg]


def _agg_bytes(agg_json) -> list[tuple[bytes, bytes]]:
    return [(bytes.fromhex(x["a"]), bytes.fromhex(x["b"])) for x in agg_json]


def _move_vote(results: list[dict], take_one: bool) -> list[dict]:
    """One vote fewer for the first candidate that has one; with take_one False the vote goes to the next candidate."""
    out = [dict(r) for r in results]
    i = next((j for j, r in enumerate(out) if r["votes"] > 0), None)
    if i is None:
        raise t01.Stop("no candidate has a vote")
    out[i]["votes"] -= 1
    if not take_one:
        out[(i + 1) % len(out)]["votes"] += 1
    return out


def make_hook(variant: str):
    def hook(ctx, k: int) -> int:
        c, auth, rec = ctx["client"], ctx["auth"], ctx["rec"]
        eid = check_election_id(ctx["election_id"])
        B = ctx["bucket"]
        keys = _secrets(t01.ORGS)

        # 1) the window ends, CLOSE_FINAL is committed and settled: the tally input is served
        t01.log("waiting for the close and the tally input")
        inp = t01.poll(lambda: (r := c.get(f"/v1/public/elections/{eid}/tally-input")).status_code == 200 and r.json(),
                       ctx["window_end"] - time.time() + 600, "tally input (CLOSE_FINAL settled)")
        F, N = inp["final_checkpoint"], len(inp["ballots"])
        cts = _ballot_cts(inp)
        n = len(inp["candidate_ids"])
        agg = elgamal.aggregate([x for _, x in cts], n)
        if _agg_json(agg) != inp["aggregate"] or inp["valid_ballots"] != N:
            raise t01.Stop("Core's aggregate is not the sum of the listed ballots (an honest start is needed)")
        rec["tally"] = {"final_checkpoint": F, "ballots": N}

        # 2) the three organizations' honest shares (the trustee check is the web / CLI tool's; here only the sum)
        for org, x in keys.items():
            share = elgamal.decryption_share(x, org, eid, agg)
            t01.expect(c.post(f"/v1/public/elections/{eid}/decryption-shares", json=share), 200)
        t01.log(f"F = {F}, {N} ballots; three honest shares accepted")

        # 3) run the tally early in a time bucket, then change TALLY_PUBLISHED in the outbox before it is released
        wait = (2 - time.time() % B) % B
        time.sleep(wait)
        tally = None
        for _ in range(30):
            r = c.post(f"/v1/elections/{eid}/tally", headers=auth)
            if r.status_code == 200:
                tally = r.json()
                break
            if r.status_code == 409 and r.json().get("code") == "OUTBOX_NOT_DRAINED":
                time.sleep(B - time.time() % B + 2)
                continue
            t01.expect(r, 200)
        if tally is None:
            raise t01.Stop("the tally kept answering OUTBOX_NOT_DRAINED")
        row = psql(f"SELECT event_id || '|' || status || '|' || extract(epoch FROM bucket_start)::bigint || '|' || "
                   f"(event->'payload')::text FROM credential.outbox "
                   f"WHERE election_id = '{eid}' AND event->>'type' = 'TALLY_PUBLISHED';")
        if len(row) != 1:
            raise t01.Stop(f"{len(row)} TALLY_PUBLISHED rows")
        ev_id, status, bucket_start, payload_text = row[0].split("|", 3)
        release = int(bucket_start) + B          # core/app/outbox.py next_unit: released once its bucket has ended
        if status != "PENDING":
            raise t01.Stop(f"TALLY_PUBLISHED already {status} before the change")
        payload = json.loads(payload_text)
        result = {"election_id": eid} | {k2: v for k2, v in payload.items() if k2 != "result_hash"}
        honest = [b for b, _ in cts]
        if _payload_of(result) != payload or result["ballot_set_root"] != hashing.ballot_set_root(honest) \
                or result["final_checkpoint"] != F or result["ballot_count"] != N or result["invalid_ballots"]:
            raise t01.Stop("the honest TALLY_PUBLISHED payload is not what the label's conditions start from")

        new_shares = None
        if variant == "T15a-results":
            result["ballot_count"] = N - 1
            result["results"] = _move_vote(result["results"], take_one=True)
        elif variant == "T15a-aggregate":
            short = elgamal.aggregate([x for _, x in cts[1:]], n)      # the first ballot (by ballot_hash) left out
            new_shares = {org: elgamal.decryption_share(x, org, eid, short) for org, x in keys.items()}
            votes = elgamal.combine(short, list(new_shares.values()), N - 1)
            result["ballot_count"] = N - 1
            result["results"] = [{"candidate_id": r["candidate_id"], "votes": v}
                                 for r, v in zip(result["results"], votes)]
        elif variant == "T15b":
            result["results"] = _move_vote(result["results"], take_one=False)
        elif variant == "T15c":
            result["ballot_set_root"] = hashing.ballot_set_root(honest + [secrets.token_hex(32)])
        elif variant == "T15d":
            result["final_checkpoint"] = F - 1
        new_payload = _payload_of(result)
        event_text = json.dumps(new_payload, separators=(",", ":"))
        share_texts = {org: json.dumps(s, separators=(",", ":")) for org, s in (new_shares or {}).items()}
        if not EVENT_ID.fullmatch(ev_id) or not all(SAFE_JSON.fullmatch(x) for x in [event_text, *share_texts.values()]):
            raise t01.Stop("unexpected characters in the changed payload or shares; not put into SQL")
        ph = hashing.Hc(new_payload)
        # Core reads a PENDING row without a lock and marks it only when the Gateway answers, so a row that has just
        # been read for delivery still looks PENDING: change it only with a margin before its release (checked again
        # on the ledger below)
        seconds_left = round(release - time.time(), 1)
        if seconds_left < 10:
            raise t01.Stop(f"only {seconds_left} s before the release of TALLY_PUBLISHED; not changed")
        # one statement: the shares (T15a-aggregate) are replaced only if the outbox row was still PENDING
        sql = (f"WITH o AS (UPDATE credential.outbox SET event = jsonb_set(jsonb_set(event, '{{payload}}', "
               f"CAST('{event_text}' AS jsonb)), '{{payload_hash}}', to_jsonb('{ph}'::text)), payload_hash = '{ph}' "
               f"WHERE event_id = '{ev_id}' AND status = 'PENDING' RETURNING 1)")
        for i, (org, s) in enumerate(share_texts.items()):
            sql += (f", s{i} AS (UPDATE credential.decryption_shares SET share = CAST('{s}' AS jsonb) "
                    f"WHERE election_id = '{eid}' AND org_id = '{org}' AND EXISTS (SELECT 1 FROM o) RETURNING 1)")
        sql += " SELECT (SELECT count(*) FROM o)" + "".join(f" + (SELECT count(*) FROM s{i})"
                                                           for i in range(len(share_texts))) + ";"
        out = psql(sql)
        expected_rows = 1 + len(share_texts)
        if out != [str(expected_rows)]:
            raise t01.Stop(f"the change hit {out} rows (expected {expected_rows}); the event may have left")
        rec["injection"] = {"kind": f"TALLY_PUBLISHED changed in the outbox ({variant})",
                            "shares_replaced": bool(new_shares), "seconds_before_release": seconds_left}
        t01.log(f"TALLY_PUBLISHED changed ({variant}), {seconds_left} s before its release")

        # 4) the Gateway's outcome; the TALLY checkpoint follows an ACCEPTED TALLY_PUBLISHED
        def outcome():
            r2 = psql(f"SELECT status || '|' || coalesce(reject_code, '') FROM credential.outbox "
                      f"WHERE event_id = '{ev_id}';")
            return bool(r2) and not r2[0].startswith("PENDING") and r2[0]
        status, code = t01.poll(outcome, B + 300, "the Gateway's outcome for TALLY_PUBLISHED").split("|")
        rec["injection"]["gateway_outcome"] = {"status": status, "reject_code": code or None}
        t01.log(f"Gateway outcome for TALLY_PUBLISHED: {status} {code}")
        if variant == "T15d":
            # LABELS_T15.md: the contract reverts InvalidFinalCheckpoint, the Gateway answers INVALID_STATE_TRANSITION
            if (status, code) != ("REJECTED", "INVALID_STATE_TRANSITION"):
                raise t01.Stop(f"TALLY_PUBLISHED {status} {code} (the label needs REJECTED INVALID_STATE_TRANSITION)")
            rej = _ledger(f"/v1/rejections?election_id={eid}")
            rec["injection"]["refusal_detail"] = details = [x.get("detail") for x in rej
                                                            if x.get("type") == "TALLY_PUBLISHED"]
            if not any("InvalidFinalCheckpoint" in (d or "") for d in details):
                raise t01.Stop(f"the refusal is not the contract's InvalidFinalCheckpoint: {details}")
            if psql(f"SELECT checkpoint FROM credential.checkpoints WHERE election_id = '{eid}' AND reason = 'TALLY';"):
                raise t01.Stop("a TALLY checkpoint exists after the refusal")
            ctx["expected_alerts"] = {"TRANSITION_REJECTED": 1}   # Core keeps TALLIED with this alert (STRICT_KEPT)
            return F
        if status not in ("ACCEPTED", "DUPLICATE"):   # DUPLICATE: stored on an earlier RETRY_LATER (Core: as ACCEPTED)
            raise t01.Stop(f"TALLY_PUBLISHED {status} {code} (the label needs it ACCEPTED)")
        # the ledger holds the changed tally, not the honest one (a delivery that read the row before the change)
        on_ledger = [x["payload"] for x in _ledger(f"/v1/events?election_id={eid}&type=TALLY_PUBLISHED")]
        rec["injection"]["ledger_has_changed_tally"] = on_ledger == [new_payload]
        if on_ledger != [new_payload]:
            raise t01.Stop("the ledger's TALLY_PUBLISHED is not the changed one")
        tk = t01.poll(lambda: psql(f"SELECT checkpoint FROM credential.checkpoints WHERE election_id = '{eid}' "
                                   "AND reason = 'TALLY';"), B + 300, "the TALLY checkpoint")
        return int(tk[0])
    return hook


VARIANTS = {v: {"after_close": make_hook(v)} for v in
            ("T15a-results", "T15a-aggregate", "T15b", "T15c", "T15d")}


def main(variant: str, argv=None) -> int:
    return t01.main(argv, scenario=variant, folder=HERE / variant, hooks=VARIANTS[variant])


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in VARIANTS:
        sys.exit(f"usage: {sys.argv[0]} {{{','.join(VARIANTS)}}} [T01 options]")
    sys.exit(main(sys.argv[1], sys.argv[2:]))
