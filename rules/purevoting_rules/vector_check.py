"""Compare an independent implementation to all committed hash test vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from . import hashing as hashes


def _calculate(name: str, value: Any) -> str:
    exact: dict[str, Callable[[Any], str]] = {
        "H_empty": hashes.H,
        "H_text": hashes.H,
        "canonical": lambda item: hashes.canonical(item).decode("utf-8"),
        "Hc": hashes.Hc,
        "set_root_dedup": hashes.set_root,
        "rejections_root": hashes.rejections_root,
        "rejections_root_none": hashes.rejections_root,
        "token_hash": hashes.token_hash,
        "nullifier_hash": hashes.nullifier_hash,
        # The committed vector encodes raw sealed-ballot bytes as hexadecimal.
        "ballot_hash": lambda item: hashes.ballot_hash(bytes.fromhex(item)),
        "receipt_hash": lambda item: hashes.receipt_hash(**item),
        "roster_hash": hashes.roster_hash,
        "token_set_root": hashes.token_set_root,
        "config_hash": hashes.config_hash,
        "ballot_set_root_duplicates": hashes.ballot_set_root,
        "result_hash": hashes.result_hash,
        "idh": lambda item: hashes.idh(item).hex(),
        "request_digest": lambda item: hashes.proposal_digest(*item),
        "approval_digest": lambda item: hashes.proposal_digest(*item),
        "finding_record_digest": lambda item: hashes.finding_record_digest(*item),
        "review_digest": lambda item: hashes.review_digest(*item),
    }
    if name in exact:
        return exact[name](value)
    if name in {f"merkle_root_{count}" for count in (0, 1, 2, 3, 5)}:
        return hashes.merkle_root(value)
    if name in {"leaf_hash_token_used", "leaf_hash_election_created"}:
        return hashes.leaf_hash(value)
    if name in {"payload_hash_token_used", "payload_hash_election_created"}:
        return hashes.payload_hash(value)
    if name in {"rejection_leaf_0", "rejection_leaf_1"}:
        return hashes.rejection_leaf(value)
    if name in {f"target_hash_{action}" for action in hashes.ACTION_CODES}:
        return hashes.target_hash(value)
    if name in {"snapshot_hash_roster", "snapshot_hash_ballot_receipts"}:
        return hashes.snapshot_hash(value)
    raise ValueError(f"No independent implementation registered for vector {name!r}")


def verify_vectors(path: Path) -> list[dict[str, Any]]:
    """Return a result per supplied vector; never regenerate its expected value.

    Digest mismatches are reported as passed=False with expected/actual values.
    Malformed files, duplicate names, or unknown vector names raise ValueError
    so an incomplete or unsupported reference cannot appear to pass silently.
    """
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read hash vectors from {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("vectors"), list):
        raise ValueError("Hash vector document must contain a vectors array")
    if not document["vectors"]:
        raise ValueError("Hash vector document must not contain an empty vector set")
    results = []
    names = set()
    for vector in document["vectors"]:
        if not isinstance(vector, dict) or not {"name", "input", "expected"} <= vector.keys():
            raise ValueError("Every hash vector must have name, input, and expected fields")
        name = vector["name"]
        if not isinstance(name, str) or name in names:
            raise ValueError(f"Invalid or duplicate hash vector name: {name!r}")
        names.add(name)
        if not isinstance(vector["expected"], str):
            raise ValueError(f"Expected output must be text for vector {name!r}")
        try:
            actual = _calculate(name, vector["input"])
        except (TypeError, ValueError, KeyError, IndexError) as exc:
            raise ValueError(f"Cannot evaluate vector {name!r}: {exc}") from exc
        results.append({
            "name": name,
            "passed": actual == vector["expected"],
            "actual": actual,
            "expected": vector["expected"],
        })
    return results
