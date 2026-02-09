"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration — values sourced from env / .env file."""

    # ── Database ────────────────────────────────
    database_url: str = "postgresql+asyncpg://soc_admin:changeme_in_production@localhost:5432/soc_network"
    database_url_sync: str = "postgresql://soc_admin:changeme_in_production@localhost:5432/soc_network"
    db_pool_size: int = 20
    db_max_overflow: int = 10

    # ── Redis ───────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── API ─────────────────────────────────────
    api_prefix: str = "/api"
    cors_origins: str = "http://localhost:3000,http://localhost:5173"
    log_level: str = "info"
    workers: int = 2

    # ── Scanner ─────────────────────────────────
    nmap_path: str = "/usr/bin/nmap"
    rustscan_path: str = "/usr/bin/rustscan"
    scan_timeout_per_host: int = 120          # seconds
    rustscan_batch_size: int = 3000           # parallel connections
    max_concurrent_scans: int = 4
    worker_concurrency: int = 4

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}


settings = Settings()
