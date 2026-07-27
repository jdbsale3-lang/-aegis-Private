# AEGIS Advanced Defenses - API Router

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field

from modules.advanced_defenses.engine import AdvancedDefenses

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/advanced", tags=["advanced-defenses"])

_engine: Optional[AdvancedDefenses] = None


def get_engine() -> AdvancedDefenses:
    global _engine
    if _engine is None:
        _engine = AdvancedDefenses()
    return _engine


class MultiModalRequest(BaseModel):
    text_prompt: str
    image_description: Optional[str] = None


class MultiModalResponse(BaseModel):
    threat_detected: bool
    threat_score: float
    threat_type: str
    details: list[str]
    confidence: float


class WatermarkRequest(BaseModel):
    text: str


class WatermarkResponse(BaseModel):
    watermarked_text: str
    watermark_id: str
    watermark_details: dict


class VectorPinRequest(BaseModel):
    vector_id: str
    vector: list[float]
    source: str


class VectorPinResponse(BaseModel):
    pin: str


class VectorVerifyRequest(BaseModel):
    vector_id: str
    vector: list[float]
    claimed_source: str
    pin: str


class VectorVerifyResponse(BaseModel):
    verified: bool
    origin: str
    tamper_score: float
    details: str


class MilvusCheckRequest(BaseModel):
    version: str
    connection_string: str = ""


class MilvusCheckResponse(BaseModel):
    vulnerable: bool
    cve: str
    cvss: float
    detail: str


class LangChainAuditRequest(BaseModel):
    version: str
    serialized_data: str = ""


class LangChainAuditResponse(BaseModel):
    vulnerable: bool
    findings: list[dict]
    risk_score: float


@router.post("/multi-modal", response_model=MultiModalResponse)
async def analyze_multi_modal(
    request: MultiModalRequest,
    engine: AdvancedDefenses = Depends(get_engine),
):
    """Detect multi-modal injection attacks across text and image modalities."""
    result = engine.analyze_multi_modal(request.text_prompt, request.image_description)
    return MultiModalResponse(
        threat_detected=result.threat_detected,
        threat_score=result.threat_score,
        threat_type=result.threat_type,
        details=result.details,
        confidence=result.confidence,
    )


@router.post("/watermark/lord-resistant", response_model=WatermarkResponse)
async def apply_lord_watermark(
    request: WatermarkRequest,
    engine: AdvancedDefenses = Depends(get_engine),
):
    """Apply a multi-layer LoRD-resistant watermark to model output."""
    watermarked, wm_id, details = engine.apply_lord_resistant_watermark(request.text)
    return WatermarkResponse(
        watermarked_text=watermarked,
        watermark_id=wm_id,
        watermark_details=details,
    )


@router.post("/vectorpin/create", response_model=VectorPinResponse)
async def create_vector_pin(
    request: VectorPinRequest,
    engine: AdvancedDefenses = Depends(get_engine),
):
    """Create a cryptographic pin for a vector to verify its origin."""
    pin = engine.pin_vector(request.vector_id, request.vector, request.source)
    return VectorPinResponse(pin=pin)


@router.post("/vectorpin/verify", response_model=VectorVerifyResponse)
async def verify_vector_pin(
    request: VectorVerifyRequest,
    engine: AdvancedDefenses = Depends(get_engine),
):
    """Verify a vector's origin using its cryptographic pin."""
    result = engine.verify_vector_pin(
        request.vector_id, request.vector, request.claimed_source, request.pin
    )
    return VectorVerifyResponse(
        verified=result.verified,
        origin=result.origin,
        tamper_score=result.tamper_score,
        details=result.details,
    )


@router.post("/audit/milvus", response_model=MilvusCheckResponse)
async def check_milvus(
    request: MilvusCheckRequest,
    engine: AdvancedDefenses = Depends(get_engine),
):
    """Check if a Milvus deployment is vulnerable to CVE-2025-64513."""
    result = engine.check_milvus_vulnerability(request.version, request.connection_string)
    return MilvusCheckResponse(
        vulnerable=result.vulnerable,
        cve=result.cve,
        cvss=result.cvss,
        detail=result.detail,
    )


@router.post("/audit/langchain", response_model=LangChainAuditResponse)
async def audit_langchain(
    request: LangChainAuditRequest,
    engine: AdvancedDefenses = Depends(get_engine),
):
    """Audit LangChain for CVE-2025-68664/68665 lc-key injection."""
    result = engine.audit_langchain(request.version, request.serialized_data)
    return LangChainAuditResponse(
        vulnerable=result.vulnerable,
        findings=result.findings,
        risk_score=result.risk_score,
    )


@router.get("/health")
async def health_check():
    return {"module": "advanced_defenses", "status": "healthy", "version": "1.0.0"}