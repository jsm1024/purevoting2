"""Errors as application/problem+json (RFC 9457) with `code` from common.schema.json ProblemCode."""
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class Problem(Exception):
    def __init__(self, status: int, code: str, detail: str | None = None):
        self.status = status
        self.code = code
        self.detail = detail


def _body(status: int, code: str, detail: str | None) -> dict:
    body = {"type": "about:blank", "title": code.replace("_", " ").lower(), "status": status, "code": code}
    if detail:
        body["detail"] = detail
    return body


async def problem_handler(_: Request, exc: Problem):
    return JSONResponse(_body(exc.status, exc.code, exc.detail), status_code=exc.status,
                        media_type="application/problem+json")


async def validation_handler(_: Request, exc: RequestValidationError):
    # field locations only; the submitted values may contain tokens or credentials and are not echoed
    where = "; ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors())[:500]
    return JSONResponse(_body(400, "VALIDATION_ERROR", where), status_code=400, media_type="application/problem+json")
