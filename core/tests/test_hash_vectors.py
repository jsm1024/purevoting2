"""Core must reproduce every shared vector in tests/vectors/hash-vectors.json (system-design section 7, #3)."""
import json
from pathlib import Path

import pytest

from app import hashing as h

VECTORS = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "hash-vectors.json"


def compute(name: str, inp):
    """How Core computes the value of each vector, by name."""
    if name in ("H_empty", "H_text", "token_hash", "nullifier_hash"):
        return h.H(inp)
    if name == "canonical":
        return h.canonical(inp)
    if name in ("Hc", "config_hash", "result_hash") or name.startswith("payload_hash_"):
        return h.Hc(inp)
    if name.startswith("merkle_root_"):
        return h.merkle_root(inp)
    if name == "set_root_dedup":
        return h.set_root(inp)
    if name.startswith("leaf_hash_"):
        return h.leaf_hash(inp)
    if name.startswith("rejection_leaf_"):
        return h.rejection_leaf(inp)
    if name in ("rejections_root", "rejections_root_none"):
        return h.rejections_root(inp)
    if name == "ballot_hash":
        return h.H(bytes.fromhex(inp))
    if name == "receipt_hash":
        return h.receipt_hash(inp["election_id"], inp["nullifier_hash"], inp["ballot_hash"])
    if name == "roster_hash":
        return h.roster_hash(inp)
    if name == "token_set_root":
        return h.token_set_root(inp)
    if name.startswith("target_hash_"):
        return h.target_hash(inp["election_id"], inp["action_id"], inp["action_type"], inp["target"])
    if name == "ballot_set_root_duplicates":
        return h.ballot_set_root(inp)
    if name.startswith("snapshot_hash_"):
        return h.snapshot_hash(inp)
    if name == "idh":
        return h.idh(inp).hex()
    if name in ("request_digest", "approval_digest"):
        return h.proposal_digest(*inp)
    if name == "finding_record_digest":
        return h.finding_digest(*inp)
    if name == "review_digest":
        return h.review_digest(*inp)
    raise KeyError(name)


def load():
    return json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", load(), ids=lambda v: v["name"])
def test_vector(vector):
    try:
        got = compute(vector["name"], vector["input"])
    except KeyError:
        pytest.fail(f"no Core computation for new vector {vector['name']!r} — add it to compute()")
    assert got == vector["expected"]


def test_vector_count():
    # a new vector must be handled explicitly, never skipped
    assert len(load()) == 39
