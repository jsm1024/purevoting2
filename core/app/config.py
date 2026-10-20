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
    # pinned chain configuration (chain-interface.md); used by the creation check
    chain_id: str = ""
    contract_address: str = ""
    pinned_node_url: str = ""


settings = Settings()
