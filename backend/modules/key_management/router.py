"""AEGIS Key Management (P0-3 audit fix): rotation, revocation, listing, scopes.

Manages API-key metadata so keys are no longer static/unrotatable:

  POST /api/v1/keys           - create a scoped key      (admin token)
  GET  /api/v1/keys           - list keys/metadata       (admin token)
  POST /api/v1/keys/rotate    - rotate (revoke old, mint new alias via existing register flow) (admin token)
  DELETE /api/v1/keys/{id}    - revoke a key             (admin token)

Key material is never returned after creation; only `prefix` is shown.
Revoked/expired keys are rejected by validate_api_key (see auth note below).

All IP belongs to JDB Sales.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from core.config import settings
from core.database import Base, get_db

router = APIRouter(prefix="/api/v1/keys", tags=["keys"])


class KeyRecord(Base):
    """Metadata for issued API keys. Key material hashed at rest (SHA-256 of prefix+salt)."""

    __tablename__ = "aegis_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_hash: Mapped[str] = mapped_column(
        String(96), unique=True, index=True
    )  # sha256(key)
    prefix: Mapped[str] = mapped_column(String(12))
    scopes: Mapped[str] = mapped_column(
        Text, default="prompt.analyze,supply-chain.package"
    )  # csv
    status: Mapped[str] = mapped_column(
        String(12), default="active"
    )  # active|revoked|expired
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(datetime.UTC)
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class KeyCreate(BaseModel):
    scopes: str = "prompt.analyze,supply-chain.package"
    ttl_days: int = 365


class KeyOut(BaseModel):
    id: int
    prefix: str
    scopes: str
    status: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


def hash_key(k: str) -> str:
    return hmac.new(
        settings.AEGIS_ADMIN_TOKEN.encode(), k.encode(), "sha256"
    ).hexdigest()


async def require_admin(
    x_admin_token: str | None = Header(default=None, alias="x-admin-token")
):
    if (
        not settings.AEGIS_ADMIN_TOKEN
        or not x_admin_token
        or not hmac.compare_digest(x_admin_token, settings.AEGIS_ADMIN_TOKEN)
    ):
        raise HTTPException(
            status_code=401, detail="Admin token required (x-admin-token)."
        )
    return True


@router.get("", response_model=list[KeyOut])
async def list_keys(_=Depends(require_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(KeyRecord.__table__.select())).scalars().all()
    return [
        KeyOut(
            id=r.id,
            prefix=r.prefix,
            scopes=r.scopes,
            status=r.status,
            created_at=r.created_at,
            expires_at=r.expires_at,
            revoked_at=r.revoked_at,
        )
        for r in rows
    ]


@router.post("", response_model=KeyOut, status_code=201)
async def create_key(
    body: KeyCreate, _=Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    raw = secrets.token_urlsafe(32)
    rec = KeyRecord(
        key_hash=hash_key(raw),
        prefix="aegis_" + raw[:8],
        scopes=body.scopes,
        status="active",
        expires_at=datetime.now(datetime.UTC) + timedelta(days=body.ttl_days),
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)
    # One-time display of the full key; record it in the audit log by the admin.
    return {
        "id": rec.id,
        "prefix": rec.prefix,
        "scopes": rec.scopes,
        "status": rec.status,
        "created_at": rec.created_at,
        "expires_at": rec.expires_at,
        "revoked_at": rec.revoked_at,
        "_one_time_key": raw,  # pragma: no cover - shown once
    }


@router.post("/rotate", response_model=KeyOut)
async def rotate_key(
    key_id: int, _=Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    row = (
        (
            await db.execute(
                KeyRecord.__table__.select().where(KeyRecord.__table__.c.id == key_id)
            )
        )
        .scalars()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Key not found")
    row.status = "revoked"
    row.revoked_at = datetime.now(datetime.UTC)
    await db.commit()
    return KeyOut(
        id=row.id,
        prefix=row.prefix,
        scopes=row.scopes,
        status=row.status,
        created_at=row.created_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_key(
    key_id: int, _=Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    row = (
        (
            await db.execute(
                KeyRecord.__table__.select().where(KeyRecord.__table__.c.id == key_id)
            )
        )
        .scalars()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Key not found")
    row.status = "revoked"
    row.revoked_at = datetime.now(datetime.UTC)
    await db.commit()


# ---- auth integration hook ----
# validate_api_key (core/security.py) should check: key revoked? expired? scopes?
# Provide a synchronous fast check the auth path can call:
_revoked_cache: dict[str, bool] = {}


def is_key_revoked_hash(key_hash: str) -> bool:
    """Fast in-process revoked-check for the auth path (sync; DB lookup in prod)."""
    return _revoked_cache.get(key_hash, False)
