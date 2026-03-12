"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration — values sourced from env / .env file."""

    # ── Database ────────────────────────────────
    database_url: str = "postgresql+asyncpg://soc_admin:changeme_in_production@db:5432/soc_network"
    database_url_sync: str = "postgresql://soc_admin:changeme_in_production@db:5432/soc_network"
    db_pool_size: int = 20
    db_max_overflow: int = 10

    # ── Redis ───────────────────────────────────
    redis_url: str = "redis://redis:6379/0"

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
    scan_interface: str = "eth0"

    # ── Firmware Analysis ───────────────────────
    emba_path: str = "/opt/emba/emba"
    emba_home: str = "/opt/emba"
    emba_timeout: int = 1800                     # 30 minutes max per device
    emba_gpt_level: str = "1"                    # 1=scripts/configs, 2=+binary
    emba_profile: str = "default-scan.emba"
    emba_fast_mode: str = "0"
    emba_modules: str = "p05,s10,s20,s40"
    triage_max_findings: int = 120
    emba_container_name: str = "soc_emba"
    firmware_dir: str = "/app/firmware"
    emba_logs_dir: str = "/app/emba_logs"

    # ── Ollama (local LLM for AI triage) ────────
    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "qwen3.5:4b"

    # ── Pipeline timeouts & retries ─────────────
    pipeline_timeout: int = 3600              # 1-hour hard cap for full pipeline
    download_max_retries: int = 3
    firmware_min_size_bytes: int = 1_000_000  # reject files < 1 MB
    triage_num_predict_steps: str = "4096,2048,1024"  # comma-separated

    # ── Alerting ─────────────────────────────────
    alert_risk_threshold: float = 7.0
    slack_webhook_url: str = ""
    alert_email: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}


settings = Settings()
