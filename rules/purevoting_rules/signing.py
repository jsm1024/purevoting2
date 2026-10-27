"""Local EIP-191 signing for the simulation's finding-record submissions.

Uses eth-account 0.13.5's documented sign_message/recover_message APIs:
https://eth-account.readthedocs.io/en/v0.13.5/eth_account.html

No Ethereum connection or registry is simulated by this module. Verifying a
signature proves its claimed key signed a digest; the integration adapter must
also compare that key to the registered Rule Engine signer. An ephemeral key is
created by default and is never logged, exported, or written to disk.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys.constants import SECPK1_N
from eth_keys.exceptions import BadSignature
from eth_utils.exceptions import ValidationError

from .hashing import h32


_ADDRESS = re.compile(r"0x[0-9a-f]{40}\Z")
_SIGNATURE = re.compile(r"0x[0-9a-f]{130}\Z")


class EIP191Signer:
    """Sign the digest's 32 raw bytes using a local secp256k1 account.

    Supplying a key is optional, for in-memory integration or tests only. This
    class neither loads a key from configuration nor persists one. Production
    key custody and on-chain registration remain separate deployment work.
    """

    __slots__ = ("__account",)

    def __init__(self, private_key: str | bytes | int | None = None) -> None:
        if private_key is None:
            self.__account = Account.create()
        else:
            try:
                self.__account = Account.from_key(private_key)
            except (ValueError, TypeError, ValidationError):
                # Do not include caller key material in exception messages.
                raise ValueError("Expected a valid secp256k1 private key") from None

    @property
    def address(self) -> str:
        return self.__account.address.lower()

    def __repr__(self) -> str:
        return f"EIP191Signer(address={self.address!r})"

    def sign_digest(self, hex_digest: str) -> dict[str, str]:
        raw = h32(hex_digest)
        # primitive=raw signs 32 bytes. text=hex_digest would sign 64 characters
        # with the wrong Ethereum message prefix and violate the contract.
        signed = self.__account.sign_message(encode_defunct(primitive=raw))
        return {
            "scheme": "eip191-secp256k1",
            "signer": self.address,
            "value": "0x" + bytes(signed.signature).hex(),
        }


def verify_signature(digest: str, signature: Mapping[str, Any]) -> bool:
    """Fail closed on malformed input or a signature from a different key.

    This checks the frozen wire representation (including v=27/28), the signed
    digest, and the claimed address. It does not establish registry membership.
    """
    try:
        raw = h32(digest)
        if not isinstance(signature, Mapping) or set(signature) != {"scheme", "signer", "value"}:
            return False
        if signature["scheme"] != "eip191-secp256k1":
            return False
        address, value = signature["signer"], signature["value"]
        if not isinstance(address, str) or not _ADDRESS.fullmatch(address):
            return False
        if not isinstance(value, str) or not _SIGNATURE.fullmatch(value):
            return False
        signature_bytes = bytes.fromhex(value[2:])
        r = int.from_bytes(signature_bytes[:32], "big")
        s = int.from_bytes(signature_bytes[32:64], "big")
        if signature_bytes[64] not in {27, 28} or not (0 < r < SECPK1_N and 0 < s < SECPK1_N):
            return False
        recovered = Account.recover_message(
            encode_defunct(primitive=raw), signature=signature_bytes
        )
        return recovered.lower() == address
    except (ValueError, TypeError, BadSignature, ValidationError, OverflowError):
        return False
