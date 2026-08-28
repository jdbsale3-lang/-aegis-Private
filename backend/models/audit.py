# AEGIS - Audit Log Model

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class AuditLog(Base):
    """Partitioned by created_at - use time-based partitioning in production."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # prompt_defense | agent_auth | mcp_gateway
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # block | allow | flag | error
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    request_body: Mapped[dict] = mapped_column(JSONB, nullable=True)
    response: Mapped[dict] = mapped_column(JSONB, nullable=True)
    verdict: Mapped[str] = mapped_column(String(50), nullable=True)
    score: Mapped[float] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=True)
    metadata: Mapped[dict] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
    )


class AttackSignature(Base):
    __tablename__ = "attack_signatures"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pattern: Mapped[str] = mapped_column(String(2000), nullable=False)
    category: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # direct_injection | indirect | role_play | encoding | jailbreak
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium"
    )  # critical | high | medium | low
    description: Mapped[str] = mapped_column(String(1000), nullable=True)
    reference: Mapped[str] = mapped_column(
        String(500), nullable=True
    )  # CVE or research link
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
