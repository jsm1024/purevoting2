"""Core settings, read from environment variables (docker-compose.yml passes them from .env)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    # postgresql+psycopg://pv2_core:<DB_CORE_PASSWORD>@db:5432/purevoting
    database_url: str = ""
    gateway_url: str = "http://ledger-gateway:8100"
    core_key: str = ""            # X-Service-Key sent to the Gateway
    rule_key: str = ""            # expected from the Rule Engine
    agent_key: str = ""           # expected from the Audit Agent
    gateway_key: str = ""         # expected from the Gateway
    jwt_secret: str = ""
    jwt_ttl_seconds: int = 8 * 3600
    # pinned chain configuration (chain-interface.md); used by the creation check
    chain_id: str = ""
    contract_address: str = ""
    pinned_node_url: str = ""
    # "node" (reads the pinned node; required for T01) or "stub" (dev only, allowed until week 3: the node is assumed to
    # hold exactly the ELECTION_CREATED values). Default node, so stub is on only when chosen explicitly.
    creation_check_mode: str = "node"
    # base of the one-time links: <voter_web_url>/vote/<election_id>#t=<token>
    voter_web_url: str = "http://127.0.0.1:5173"
    # background loops (scheduler, outbox worker); tests drive them by hand
    run_workers: bool = True


settings = Settings()
