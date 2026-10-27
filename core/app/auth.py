"""Staff login (JWT) and service keys (contracts/README.md "Permission matrix").

Staff accounts come from the setup script (app/scripts/create_staff.py); there is no account API (threat-model O1).
"""
import hashlib
import hmac
import secrets
from dataclasses import dataclass

import jwt
from fastapi import Header

from app.config import settings
from app.errors import Problem
from app.timeutil import clock

# ---- passwords (stdlib scrypt, no extra dependency) ----

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(got.hex(), dk)
    except ValueError:
        return False


# ---- staff JWT ----


@dataclass(frozen=True)
class Staff:
    user_id: str
    role: str          # admin | approver | auditor
    org_id: str
    display_name: str

    def public(self) -> dict:
        return {"user_id": self.user_id, "role": self.role, "org_id": self.org_id, "display_name": self.display_name}


def issue_token(staff: Staff) -> str:
    if not settings.jwt_secret:
        raise Problem(500, "INTERNAL_ERROR", "JWT_SECRET is not set")
    now = clock.now()
    claims = {"sub": staff.user_id, "role": staff.role, "org_id": staff.org_id, "name": staff.display_name,
              "iat": now, "exp": now + settings.jwt_ttl_seconds}
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")


def staff_from_header(authorization: str | None) -> Staff:
    if not authorization or not authorization.startswith("Bearer ") or not settings.jwt_secret:
        raise Problem(401, "UNAUTHORIZED")
    try:
        c = jwt.decode(authorization[7:], settings.jwt_secret, algorithms=["HS256"],
                       options={"verify_exp": False, "verify_iat": False})   # checked against our clock below
    except jwt.PyJWTError:
        raise Problem(401, "UNAUTHORIZED") from None
    if c.get("exp", 0) < clock.now():
        raise Problem(401, "UNAUTHORIZED", "token expired")
    return Staff(c["sub"], c["role"], c["org_id"], c.get("name", ""))


def require_staff(*roles: str):
    def dep(authorization: str | None = Header(default=None)) -> Staff:
        staff = staff_from_header(authorization)
        if staff.role not in roles:
            raise Problem(403, "FORBIDDEN")
        return staff
    return dep


# ---- service keys ----


def _service_for(key: str | None) -> str | None:
    if not key:
        return None
    for name, expected in (("rule", settings.rule_key), ("agent", settings.agent_key),
                           ("gateway", settings.gateway_key)):
        if expected and hmac.compare_digest(key, expected):
            return name
    return None


def require_service(*services: str):
    def dep(x_service_key: str | None = Header(default=None)) -> str:
        svc = _service_for(x_service_key)
        if svc not in services:
            raise Problem(403, "FORBIDDEN")
        return svc
    return dep
