"""Core API (contracts/core-api.openapi.yaml). Week 1: skeleton with health checks only."""
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app import db

app = FastAPI(title="PureVoting 2.0 — Core API", version="1.0.0")


@app.get("/healthz")
def healthz():
    """Process is up (used by the docker-compose healthcheck)."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    """Process is up and the database answers."""
    try:
        db.ping()
    except Exception:  # noqa: BLE001 — any failure means not ready; details stay out of the response
        return JSONResponse(status_code=503, content={"status": "db_unavailable"})
    return {"status": "ready"}
