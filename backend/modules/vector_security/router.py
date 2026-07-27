# AEGIS Module 7: Vector Store Security - API Router

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field

from modules.vector_security.guard import (
    VectorStoreSecurity, VectorRecord, AccessPolicy, QueryAuditEntry,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vector-security", tags=["vector-security"])

_guard: Optional[VectorStoreSecurity] = None


def get_guard() -> VectorStoreSecurity:
    global _guard
    if _guard is None:
        _guard = VectorStoreSecurity()
    return _guard


class EncryptVectorRequest(BaseModel):
    vector: list[float]


class EncryptResponse(BaseModel):
    ciphertext: str


class DecryptVectorRequest(BaseModel):
    ciphertext: str


class DecryptResponse(BaseModel):
    vector: list[float]


class CheckAccessRequest(BaseModel):
    user_id: str
    user_roles: list[str]
    collection: str


class CheckAccessResponse(BaseModel):
    granted: bool
    reason: str


class SetPolicyRequest(BaseModel):
    policy_id: str
    collection: str
    allowed_roles: list[str] = Field(default_factory=list)
    allowed_users: list[str] = Field(default_factory=list)
    max_query_rate: int = 100
    require_encryption: bool = True
    require_authentication: bool = True


class DetectReconstructionRequest(BaseModel):
    user_id: str
    collection: str
    recent_queries: list[str]


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_vector(
    request: EncryptVectorRequest,
    guard: VectorStoreSecurity = Depends(get_guard),
):
    """Encrypt a vector embedding at rest."""
    ciphertext = guard.encrypt_vector(request.vector)
    return EncryptResponse(ciphertext=ciphertext)


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_vector(
    request: DecryptVectorRequest,
    guard: VectorStoreSecurity = Depends(get_guard),
):
    """Decrypt a vector embedding."""
    vector = guard.decrypt_vector(request.ciphertext)
    return DecryptResponse(vector=vector)


@router.post("/access/check", response_model=CheckAccessResponse)
async def check_access(
    request: CheckAccessRequest,
    guard: VectorStoreSecurity = Depends(get_guard),
):
    """Check if a user has access to a collection."""
    granted, reason = guard.check_access(request.user_id, request.user_roles, request.collection)
    return CheckAccessResponse(granted=granted, reason=reason)


@router.post("/policy")
async def set_policy(
    request: SetPolicyRequest,
    guard: VectorStoreSecurity = Depends(get_guard),
):
    """Set an access policy for a vector collection."""
    policy = AccessPolicy(
        policy_id=request.policy_id,
        collection=request.collection,
        allowed_roles=request.allowed_roles,
        allowed_users=request.allowed_users,
        max_query_rate=request.max_query_rate,
        require_encryption=request.require_encryption,
        require_authentication=request.require_authentication,
    )
    guard.set_policy(policy)
    return {"status": "policy set", "collection": request.collection}


@router.post("/detect-reconstruction")
async def detect_reconstruction(
    request: DetectReconstructionRequest,
    guard: VectorStoreSecurity = Depends(get_guard),
):
    """Detect potential vector reconstruction attacks."""
    alert = guard.detect_reconstruction(request.user_id, request.collection, request.recent_queries)
    if alert:
        return {"alert": alert.__dict__, "threat_detected": True}
    return {"alert": None, "threat_detected": False}


@router.get("/health")
async def health_check():
    return {"module": "vector_security", "status": "healthy", "version": "1.0.0"}