from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_without_database():
    # no DATABASE_URL in unit tests: the endpoint must answer 503, not crash
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "db_unavailable"}
