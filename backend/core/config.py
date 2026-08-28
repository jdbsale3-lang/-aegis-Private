# AEGIS Backend - Core Configuration
# Environment-based settings with secure defaults

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "AEGIS"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: list[str] = ["*"]
    API_KEY: Optional[str] = None  # Set in production

    AEGIS_ADMIN_TOKEN: str = ""  # P0-3 admin token for key management

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://aegis:aegis@localhost:5432/aegis"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40

    # Redis Cache
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 10

    # Kafka / Redpanda
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_AUDIT_TOPIC: str = "aegis-audit"
    KAFKA_ALERT_TOPIC: str = "aegis-alerts"

    # Module 1: Prompt Defense
    PROMPT_DEFENSE_MODE: str = "block"  # block | flag | monitor
    PROMPT_CLASSIFIER_THRESHOLD: float = 0.6
    PROMPT_ENSEMBLE_MODEL_PATH: str = "models/prompt_classifier"
    PROMPT_SIGNATURE_PATH: str = "models/attack_signatures.json"
    PROMPT_CACHE_TTL: int = 60  # seconds

    # Module 2: Agent Authorization
    AGENT_AUTH_CACHE_TTL: int = 300  # Policy cache TTL in seconds
    AGENT_MAX_SESSION_TTL: int = 3600  # 1 hour max session

    # Module 3: MCP Gateway
    MCP_GATEWAY_HOST: str = "0.0.0.0"
    MCP_GATEWAY_PORT: int = 8443
    MCP_GATEWAY_UPSTREAM: Optional[str] = None
    MCP_SANDBOX_ENABLED: bool = True
    MCP_MAX_TOOLS_PER_SERVER: int = 50

    # JWT
    JWT_SECRET: str = "change-me-in-production-aegis-2026"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION: int = 3600  # 1 hour

    # Alerting
    ALERT_WEBHOOK_URL: Optional[str] = None
    ALERT_SLACK_CHANNEL: Optional[str] = None
    ALERT_EMAIL_SENDER: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()