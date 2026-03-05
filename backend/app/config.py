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
    temporal_max_concurrent_activities: int = Field(default=50, ge=1, le=500)
    temporal_max_concurrent_workflow_tasks: int = Field(default=20, ge=1, le=200)

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

    # Enterprise feature flags
    enterprise_features_enabled: bool = False
    feature_auth_enterprise: bool = False
    feature_scim: bool = False
    feature_secret_store: bool = False
    feature_upload_av_scan: bool = False
    feature_signing: bool = False
    feature_tsa: bool = False
    feature_rbac_abac: bool = False
    feature_approvals: bool = False
    feature_reporting_package: bool = False
    feature_pricing: bool = False

    # External IdP / OIDC
    oidc_jwks_url: str = ''
    oidc_audience: str = ''
    oidc_token_endpoint: str = ''
    oidc_client_id: str = ''
    oidc_client_secret: str = ''
    mfa_required_sensitive: bool = False

    # Sessions
    access_token_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    refresh_token_ttl_hours: int = Field(default=72, ge=1, le=24 * 30)

    # Secret store
    secret_store_backend: str = 'env'  # env|vault
    secret_encryption_key: str = 'dev-only-key-change-me'
    vault_addr: str = 'http://vault:8200'
    vault_token: str = 'root'
    vault_mount_kv: str = 'secret'
    vault_mount_transit: str = 'transit'

    # Upload controls
    upload_default_max_mb: int = Field(default=20, ge=1, le=1024)
    clamav_host: str = 'clamav'
    clamav_port: int = 3310
    clamav_timeout_seconds: int = Field(default=10, ge=1, le=120)

    # Timestamping
    tsa_provider: str = 'stub'  # stub|external
    tsa_url: str = ''

    # Telemetry
    telemetry_enabled: bool = False
    otlp_endpoint: str = 'http://otel-collector:4317'
    metrics_enabled: bool = True

    auto_create_schema: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
