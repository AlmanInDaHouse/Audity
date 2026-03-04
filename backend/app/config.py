from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_env: str = 'dev'
    database_url: str = 'sqlite+aiosqlite:///./audity.db'
    redis_url: str = 'redis://localhost:6379/0'

    temporal_server: str = 'localhost:7233'
    temporal_namespace: str = 'default'
    temporal_task_queue: str = 'audit-run-queue'
    workflow_mode: str = 'inline'

    minio_endpoint: str = 'localhost:9000'
    minio_access_key: str = 'minioadmin'
    minio_secret_key: str = 'minioadmin'
    minio_bucket: str = 'audity-evidence'
    minio_secure: bool = False
    storage_backend: str = 'memory'  # why this: tests/local run without external object store.

    catalog_dir: str = str(Path(__file__).resolve().parents[2] / 'catalogs')

    oidc_issuer: str = 'http://localhost:8000'
    oidc_key_id: str = 'audity-dev-key'
    oidc_private_key_b64: str = ''

    api_base_url: str = 'http://localhost:8000'
    rate_limit_per_minute: int = Field(default=120, ge=10, le=5000)
    sensitive_rate_limit_per_minute: int = Field(default=20, ge=1, le=2000)

    github_token: str = ''
    google_service_account_json_b64: str = ''

    auto_create_schema: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
