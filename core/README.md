# core/ — Core API (owner: Seungmin)

Implements `contracts/core-api.openapi.yaml`. Role design: `docs/roles/core-web.md`.

| Path | What |
|---|---|
| `app/main.py` | FastAPI app (week 1: `/healthz`, `/readyz`) |
| `app/config.py`, `app/db.py` | settings from environment variables, SQLAlchemy engine |
| `app/hashing.py` | `contracts/hashing.md` (H, Hc, Merkle, roots, signature digests) |
| `db/init/00_roles.sh`, `db/init/10_schema.sql` | first-start DB setup: roles, schemas `credential` / `ballot`, tables, SECURITY DEFINER ballot functions |
| `db/tests/smoke.sql` | executed by CI against PostgreSQL 16 as `pv2_core` |
| `tests/` | unit tests incl. the 39 shared hash vectors (`tests/vectors/hash-vectors.json`) |

```bash
# unit tests (no database needed)
cd core && pip install -r requirements-dev.txt && pytest -q

# full stack (needs Docker): from the repository root, after copying .env.example to .env
docker compose up --build        # then http://127.0.0.1:8000/readyz
```

The DB init scripts run only when the `pgdata` volume is empty; after changing them use `docker compose down -v`.
