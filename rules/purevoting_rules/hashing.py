"""Independent implementation of PureVoting 2.0's frozen v1 hash contract.

The formulas come from ``contracts/hashing.md``. No Core implementation or
reference-vector generator is imported. Schema validation is a separate concern;
these helpers validate the encodings that would otherwise change a digest.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any

import rfc8785


_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SAFE_JSON_INTEGER = (1 << 53) - 1

ACTION_CODES = {
    "ROSTER_AMEND": 1,
    "TOKEN_REISSUE": 2,
    "WINDOW_CHANGE": 3,
    "ELECTION_CLOSE_EARLY": 4,
    "ELECTION_VOID": 5,
}
PROPOSAL_CODES = {"REQUEST": 0, "APPROVE": 1, "REJECT": 2}
RULE_CODES = {f"R{number}": number for number in range(1, 6)}
RESULT_CODES = {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}
REVIEW_CODES = {"DISMISSED": 1, "ACCEPTED_RISK": 2, "CONFIRMED_ISSUE": 3}


def H(value: str | bytes) -> str:
    """SHA-256 of UTF-8 text or raw bytes, as lowercase 64-character hex."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, bytes):
        raise TypeError("H expects text or bytes")
    return hashlib.sha256(value).hexdigest()


def _check_json(value: Any, path: str, ancestors: set[int]) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, float):
        raise ValueError(f"Floating-point numbers are forbidden in hashed JSON at {path}")
    if isinstance(value, int):
        if not -_MAX_SAFE_JSON_INTEGER <= value <= _MAX_SAFE_JSON_INTEGER:
            raise ValueError(f"Integer outside the interoperable JCS safe range at {path}")
        return
    if isinstance(value, (dict, list)):
        marker = id(value)
        if marker in ancestors:
            raise ValueError(f"Circular JSON value at {path}")
        ancestors.add(marker)
        try:
            if isinstance(value, dict):
                for key, member in value.items():
                    if not isinstance(key, str):
                        raise TypeError(f"JSON object keys must be strings at {path}")
                    _check_json(member, f"{path}.{key}", ancestors)
            else:
                for index, member in enumerate(value):
                    _check_json(member, f"{path}[{index}]", ancestors)
        finally:
            ancestors.remove(marker)
        return
    raise TypeError(f"Unsupported JSON type {type(value).__name__} at {path}")


def canonical(value: Any) -> bytes:
    """RFC 8785 JCS bytes, with the contract's recursive no-floats rule.

    Booleans retain their JSON type. Integers outside +/- (2**53 - 1) are
    rejected rather than rounded, keeping Python and JavaScript interoperable.
    Object key ordering is JCS UTF-16 ordering, supplied by ``rfc8785``.
    """
    _check_json(value, "$", set())
    return rfc8785.dumps(value)


def Hc(value: Any) -> str:
    """SHA-256 of the canonical JSON bytes."""
    return H(canonical(value))


def h32(value: str) -> bytes:
    """Decode the contract's lowercase, unprefixed SHA-256 hex representation."""
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise ValueError("Expected exactly 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def node(left: str, right: str) -> str:
    """Hash two hexadecimal nodes concatenated as ASCII, not raw digest bytes."""
    h32(left)
    h32(right)
    return H((left + right).encode("ascii"))


def merkle_root(leaves: Iterable[str]) -> str:
    """Ordered Merkle root; an unpaired final node is carried up unchanged."""
    level = list(leaves)
    for leaf in level:
        h32(leaf)
    if not level:
        return H("")
    while len(level) > 1:
        next_level = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level
    return level[0]


def set_root(values: Iterable[str]) -> str:
    """Merkle root of a sorted set (duplicate digest strings removed)."""
    leaves = list(values)
    for leaf in leaves:
        h32(leaf)
    return merkle_root(sorted(set(leaves)))


def ballot_set_root(ballot_hashes: Iterable[str]) -> str:
    """Root of a sorted multiset: keep one leaf per accepted ballot event.

    Despite the historical name, this is deliberately NOT ``set_root``.
    Repeated ciphertext hashes must retain their multiplicity.
    """
    leaves = list(ballot_hashes)
    for leaf in leaves:
        h32(leaf)
    return merkle_root(sorted(leaves))


def _raw_base64(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise TypeError("Expected raw bytes or standard base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Expected standard RFC 4648 base64 with padding") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Expected canonical standard base64 with padding and no line breaks")
    return raw


def token_hash(token: str) -> str:
    return H(token)


def nullifier_hash(credential: str) -> str:
    return H(credential)


def ballot_hash(sealed_ballot: str | bytes) -> str:
    """Hash raw sealed-ballot bytes, decoding canonical base64 when given text."""
    return H(_raw_base64(sealed_ballot))


def public_key_hash(public_key: str | bytes) -> str:
    raw = _raw_base64(public_key)
    if len(raw) != 32:
        raise ValueError("An X25519 public key must contain exactly 32 bytes")
    return H(raw)


def receipt_hash(election_id: str, nullifier_hash: str, ballot_hash: str) -> str:
    h32(nullifier_hash)
    h32(ballot_hash)
    return Hc({
        "election_id": election_id,
        "nullifier_hash": nullifier_hash,
        "ballot_hash": ballot_hash,
    })


def payload_hash(payload: Any) -> str:
    return Hc(payload)


def leaf_hash(event: Mapping[str, Any]) -> str:
    """Hash a submission, excluding the two ledger response-only fields."""
    return Hc({key: value for key, value in event.items() if key not in {"received_at", "anchor"}})


def finding_hash(finding_submission: Mapping[str, Any]) -> str:
    """Hash exactly the submission; pass no Core review or response metadata."""
    return Hc(dict(finding_submission))


def roster_hash(active_voter_keys: Iterable[str]) -> str:
    """Caller supplies voter keys already filtered to ACTIVE at the checkpoint."""
    return set_root(H(key) for key in active_voter_keys)


def token_set_root(nonrevoked_token_hashes: Iterable[str]) -> str:
    """Caller supplies hashes already filtered to tokens that are not revoked."""
    return set_root(nonrevoked_token_hashes)


def rejection_leaf(rejection: Mapping[str, Any]) -> str:
    fields = (
        "rejection_id", "election_id", "event_id", "type", "checkpoint",
        "reject_code", "recorded_at", "payload_hash",
    )
    body = {key: rejection[key] for key in fields}
    body["subject_hash"] = rejection.get("subject_hash")
    return Hc(body)


def rejections_root(rejections: Iterable[Mapping[str, Any]]) -> str:
    return set_root(rejection_leaf(item) for item in rejections)


def snapshot_hash(rows: Iterable[Mapping[str, Any]]) -> str:
    """Hash every row exactly as returned, ordered by its unique row_key.

    Fetching all pages and selecting the checkpoint is the adapter's job.
    No row or column is dropped by this function.
    """
    ordered = [dict(row) for row in rows]
    for row in ordered:
        if not isinstance(row.get("row_key"), str):
            raise ValueError("Every snapshot row must contain a string row_key")
    return Hc(sorted(ordered, key=lambda row: row["row_key"]))


def config_hash(config: Mapping[str, Any]) -> str:
    """Hash immutable election creation configuration.

    A view row may supply config_window_start/config_window_end, which take
    precedence over the effective window_start/window_end values.
    """
    body = {key: config[key] for key in (
        "title", "time_bucket_seconds", "checkpoint_interval_seconds",
        "approval_threshold", "proposal_ttl_hours", "operator_org", "public_key_hash",
    )}
    body["window_start"] = config[
        "config_window_start" if "config_window_start" in config else "window_start"
    ]
    body["window_end"] = config[
        "config_window_end" if "config_window_end" in config else "window_end"
    ]
    body["candidates"] = sorted(
        ({"candidate_id": item["candidate_id"], "name": item["name"]} for item in config["candidates"]),
        key=lambda item: item["candidate_id"],
    )
    organizations = []
    for item in config["organizations"]:
        signer = item["signer"]
        if not isinstance(signer, str):
            raise TypeError("Organization signer must be text")
        if signer[:2].lower() == "0x":
            signer = signer.lower()
        organizations.append({"org_id": item["org_id"], "signer": signer})
    body["organizations"] = sorted(organizations, key=lambda item: item["org_id"])
    return Hc(body)


def target_hash(proposal: Mapping[str, Any]) -> str:
    """Hash a normalized proposal target; sorting never removes duplicates."""
    action_type = proposal["action_type"]
    supplied = proposal["target"]
    if action_type == "ROSTER_AMEND":
        target = {"add": sorted(supplied["add"]), "remove": sorted(supplied["remove"])}
    elif action_type == "TOKEN_REISSUE":
        target = {"voter_keys": sorted(supplied["voter_keys"])}
        if not target["voter_keys"]:
            raise ValueError("TOKEN_REISSUE target requires at least one voter key")
    elif action_type == "WINDOW_CHANGE":
        target = {"new_window_end": supplied["new_window_end"]}
    elif action_type == "ELECTION_CLOSE_EARLY":
        target = {"closed_at": supplied["closed_at"]}
    elif action_type == "ELECTION_VOID":
        target = {"finding_ids": sorted(supplied["finding_ids"])}
    else:
        raise ValueError(f"Unknown action type: {action_type!r}")
    return Hc({
        "election_id": proposal["election_id"],
        "action_id": proposal["action_id"],
        "action_type": action_type,
        "target": target,
    })


def result_hash(result: Mapping[str, Any]) -> str:
    """Hash the complete tally projection; the caller must include all candidates."""
    body = {key: result[key] for key in (
        "election_id", "final_checkpoint", "ballot_count", "invalid_ballots",
        "excluded_ballots", "ballot_set_root",
    )}
    body["results"] = sorted(
        ({"candidate_id": item["candidate_id"], "votes": item["votes"]} for item in result["results"]),
        key=lambda item: item["candidate_id"],
    )
    body["invalid_ballot_hashes"] = sorted(result["invalid_ballot_hashes"])
    return Hc(body)


def tag(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Digest tag must be text")
    raw = value.encode("ascii")
    if len(raw) > 32:
        raise ValueError("Digest tag must fit into 32 ASCII bytes")
    return raw.ljust(32, b"\0")


def idh(value: str) -> bytes:
    """The 32 raw bytes used for an on-chain ID (not its hexadecimal text)."""
    if not isinstance(value, str):
        raise TypeError("An ID must be text")
    return bytes.fromhex(H(value))


def u(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << 256):
        raise ValueError("Digest integer must be an unsigned 256-bit integer")
    return value.to_bytes(32, byteorder="big", signed=False)


def _code(value: str | int, codes: Mapping[str, int], label: str) -> int:
    if isinstance(value, str) and value in codes:
        return codes[value]
    if isinstance(value, int) and not isinstance(value, bool) and value in codes.values():
        return value
    raise ValueError(f"Unknown {label}: {value!r}")


def proposal_digest(
    proposal_id: str,
    action_id: str,
    election_id: str,
    action_type: str | int,
    target_hash: str,
    org_id: str,
    decision: str | int,
) -> str:
    return H(b"".join((
        tag("PV2-PROPOSAL-v1"), idh(proposal_id), idh(action_id), idh(election_id),
        u(_code(action_type, ACTION_CODES, "action type")), h32(target_hash), idh(org_id),
        u(_code(decision, PROPOSAL_CODES, "proposal decision")),
    )))


def finding_record_digest(
    finding_id: str,
    election_id: str,
    rule_id: str | int,
    result: str | int,
    checkpoint: int,
    finding_hash: str,
) -> str:
    return H(b"".join((
        tag("PV2-FINDING-v1"), idh(finding_id), idh(election_id),
        u(_code(rule_id, RULE_CODES, "rule")), u(_code(result, RESULT_CODES, "rule result")),
        u(checkpoint), h32(finding_hash),
    )))


def review_digest(
    finding_id: str,
    election_id: str,
    finding_hash: str,
    org_id: str,
    decision: str | int,
    note_hash: str,
) -> str:
    return H(b"".join((
        tag("PV2-REVIEW-v1"), idh(finding_id), idh(election_id), h32(finding_hash),
        idh(org_id), u(_code(decision, REVIEW_CODES, "review decision")), h32(note_hash),
    )))
