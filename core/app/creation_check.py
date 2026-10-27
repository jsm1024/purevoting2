"""Creation check (chain-interface.md "Creation check"): compare the on-chain creation fields, read directly from the
pinned node, with the ELECTION_CREATED payload. Until PASSED, Core delivers no further outbox event of the election and
refuses freeze / issue / admin actions.

Modes (CREATION_CHECK_MODE):
- `node` (default, required for T01): read electionState / electionGovernance from the pinned node. The JSON-RPC reader
  arrives in week 3 with the contract ABI; until then the check stays PENDING and is retried by the scheduler.
- `stub` (dev only, allowed until week 3 by the role design): the node is assumed to hold exactly the ELECTION_CREATED
  values. Core logs a warning at startup while it is on.
"""
import logging

from sqlalchemy import text

from app.config import settings
from app.store import raise_alert

log = logging.getLogger("core.creation_check")


def warn_if_stub() -> None:
    if settings.creation_check_mode == "stub":
        log.warning("CREATION_CHECK_MODE=stub: the creation check always passes (dev only; must be 'node' for T01)")


def run(e: dict) -> tuple[str, str | None]:
    """Returns (PENDING | PASSED | MISMATCH, detail)."""
    if settings.creation_check_mode == "stub":
        return "PASSED", None
    # week 3: read the node (retry while it is behind created_block; LEDGER_UNAVAILABLE after 60 s unreachable;
    # configHash == 0 for 60 s after the block was reached → MISMATCH "not found")
    return "PENDING", None


def apply(conn, e: dict, now: int) -> None:
    """Run the check for an election whose ELECTION_CREATED was ACCEPTED / DUPLICATE (created_block is known)."""
    if e["creation_check"] != "PENDING" or e.get("created_block") is None:
        return
    result, detail = run(e)
    if result == "PENDING":
        return
    conn.execute(text("UPDATE credential.elections SET creation_check = :c WHERE election_id = :e"),
                 {"c": result, "e": e["election_id"]})
    e["creation_check"] = result
    if result == "MISMATCH":
        raise_alert(conn, e["election_id"], 0, "GOVERNANCE_MISMATCH", "core-api", now, detail)
