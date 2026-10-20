"""Hashes, Merkle roots and signature digests exactly as defined in contracts/hashing.md.

Every function here must reproduce tests/vectors/hash-vectors.json (checked by tests/test_hash_vectors.py).
"""
import base64
import hashlib

import rfc8785

# ---- primitives ----


def H(data: bytes | str) -> str:
    """SHA-256 as 64 lowercase hex chars; a str is hashed as UTF-8."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> str:
    """RFC 8785 JSON Canonicalization Scheme (JCS). Hashed objects never contain floats."""
    return rfc8785.dumps(obj).decode("utf-8")


def Hc(obj) -> str:
    return H(rfc8785.dumps(obj))


def merkle_root(leaves: list[str]) -> str:
    """Leaves in the given order; adjacent pairs hashed as H(l + r) over the hex text; an odd node is carried up;
    one leaf = that leaf; empty list = H("")."""
    level = list(leaves)
    if not level:
        return H("")
    while len(level) > 1:
        nxt = [H(level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def set_root(values: list[str]) -> str:
    """merkle_root of the values sorted ascending with duplicates removed."""
    return merkle_root(sorted(set(values)))


def b64std(raw: bytes) -> str:
    """Base64 text inside hashed objects: RFC 4648 section 4, with padding, no line breaks."""
    return base64.b64encode(raw).decode("ascii")


# ---- values ----


def leaf_hash(event: dict) -> str:
    """Hc of the stored LedgerEventSubmission, including payload_hash, excluding received_at and anchor."""
    return Hc({k: v for k, v in event.items() if k not in ("received_at", "anchor")})


REJECTION_LEAF_FIELDS = ("rejection_id", "election_id", "event_id", "type", "checkpoint", "reject_code",
                         "recorded_at", "payload_hash", "subject_hash")


def rejection_leaf(rejection: dict) -> str:
    """Hc of the nine hashed rejection fields; subject_hash is null when absent; detail and anchor_id are not hashed."""
    return Hc({k: rejection.get(k) for k in REJECTION_LEAF_FIELDS})


def rejections_root(rejections: list[dict]) -> str:
    return set_root([rejection_leaf(r) for r in rejections])


def receipt_hash(election_id: str, nullifier_hash: str, ballot_hash: str) -> str:
    return Hc({"election_id": election_id, "nullifier_hash": nullifier_hash, "ballot_hash": ballot_hash})


def roster_hash(active_voter_keys: list[str]) -> str:
    return set_root([H(k) for k in active_voter_keys])


def token_set_root(live_token_hashes: list[str]) -> str:
    return set_root(live_token_hashes)


def ballot_set_root(ballot_hashes: list[str]) -> str:
    """One leaf per accepted BALLOT_RECEIVED: sorted, duplicates KEPT."""
    return merkle_root(sorted(ballot_hashes))


def target_hash(election_id: str, action_id: str, action_type: str, target: dict) -> str:
    return Hc({"election_id": election_id, "action_id": action_id, "action_type": action_type, "target": target})


def snapshot_hash(rows: list[dict]) -> str:
    """Hc of ALL rows of a view as of checkpoint k, sorted by row_key, each row exactly as the view returns it."""
    return Hc(sorted(rows, key=lambda r: r["row_key"]))


# ---- signature digests (fixed 32-byte binary layout) ----

ACTION_CODE = {"ROSTER_AMEND": 1, "TOKEN_REISSUE": 2, "WINDOW_CHANGE": 3, "ELECTION_CLOSE_EARLY": 4, "ELECTION_VOID": 5}
PROPOSAL_DECISION = {"REQUEST": 0, "APPROVE": 1, "REJECT": 2}
REVIEW_DECISION = {"DISMISSED": 1, "ACCEPTED_RISK": 2, "CONFIRMED_ISSUE": 3}
RULE_CODE = {"R1": 1, "R2": 2, "R3": 3, "R4": 4, "R5": 5}
RESULT_CODE = {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}


def tag(s: str) -> bytes:
    b = s.encode("ascii")
    if len(b) > 32:
        raise ValueError("tag longer than 32 bytes")
    return b + b"\x00" * (32 - len(b))


def idh(id_string: str) -> bytes:
    """sha256(utf8(id)) as 32 raw bytes — also the bytes32 ID used on chain."""
    return hashlib.sha256(id_string.encode("utf-8")).digest()


def h32(hex64: str) -> bytes:
    return bytes.fromhex(hex64)


def u(n: int) -> bytes:
    return n.to_bytes(32, "big")


def proposal_digest(proposal_id: str, action_id: str, election_id: str, action_type: str, target_hash_hex: str,
                    org_id: str, decision: int) -> str:
    """Request digest (decision 0) or approval digest (1 APPROVE / 2 REJECT)."""
    return hashlib.sha256(tag("PV2-PROPOSAL-v1") + idh(proposal_id) + idh(action_id) + idh(election_id)
                          + u(ACTION_CODE[action_type]) + h32(target_hash_hex) + idh(org_id) + u(decision)).hexdigest()


def finding_digest(finding_id: str, election_id: str, rule: int, result: int, checkpoint: int,
                   finding_hash: str) -> str:
    return hashlib.sha256(tag("PV2-FINDING-v1") + idh(finding_id) + idh(election_id) + u(rule) + u(result)
                          + u(checkpoint) + h32(finding_hash)).hexdigest()


def review_digest(finding_id: str, election_id: str, finding_hash: str, org_id: str, decision: int,
                  note_hash: str) -> str:
    return hashlib.sha256(tag("PV2-REVIEW-v1") + idh(finding_id) + idh(election_id) + h32(finding_hash)
                          + idh(org_id) + u(decision) + h32(note_hash)).hexdigest()
