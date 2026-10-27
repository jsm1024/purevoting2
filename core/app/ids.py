"""IDs (contracts/README.md "Shared conventions"): prefix + 26 Crockford base32 chars.

ULID (time-sortable) for system objects; fully random for anything on the voter side (evr_, vtr_, att_), so those IDs
carry no timestamp.
"""
import base64
import secrets
import time

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b32(n: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(CROCKFORD[n & 31])
        n >>= 5
    return "".join(reversed(out))


def ulid(prefix: str) -> str:
    """48-bit millisecond time + 80 random bits."""
    ms = int(time.time() * 1000)
    return f"{prefix}_{_b32((ms << 80) | secrets.randbits(80), 26)}"


def random_id(prefix: str) -> str:
    """26 random chars (130 bits), no timestamp."""
    return f"{prefix}_{_b32(secrets.randbits(130), 26)}"


def token128() -> str:
    """128-bit random value, base64url without padding (22 chars): voting tokens."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")
