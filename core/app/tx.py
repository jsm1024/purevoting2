"""Transaction helpers for the routes."""
from app import lifecycle, timeutil
from app.db import get_engine
from app.elections import Refused
from app.errors import Problem
from app.store import load_election, record_rejection


def run(fn):
    with get_engine().begin() as conn:
        return fn(conn)


def run_election(election_id: str, fn, missing: Problem | None = None):
    """Take the election lock, read the clock once, perform the boundary transitions due at that time (boundary
    serialization: a request with t >= T is handled after the commit / close at T, with the same t), then run
    fn(conn, e, t) in a savepoint. A Refused undoes only fn's writes and is recorded in
    rejected_attempts at the open checkpoint, in the same committed transaction, before the error is returned."""
    refused = None
    with get_engine().begin() as conn:
        try:
            e = load_election(conn, election_id, lock=True)
        except Problem:
            raise (missing or Problem(404, "NOT_FOUND")) from None
        now = timeutil.clock.now()
        lifecycle.advance(conn, e, now)
        sp = conn.begin_nested()
        try:
            out = fn(conn, e, now)
            sp.commit()
            return out
        except Refused as r:
            sp.rollback()
            record_rejection(conn, election_id, e["open_checkpoint"], r.code, r.subject_hash)
            refused = r
    raise refused
