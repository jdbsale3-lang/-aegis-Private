# AEGIS Module 6: Model Extraction Defense - API Router

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field

from modules.model_extraction.defense import ModelExtractionDefense

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/extraction-defense", tags=["extraction-defense"])

_defense: Optional[ModelExtractionDefense] = None


def get_defense() -> ModelExtractionDefense:
    global _defense
    if _defense is None:
        _defense = ModelExtractionDefense()
    return _defense


class WatermarkRequest(BaseModel):
    output: str = Field(..., min_length=1, max_length=50000)


class WatermarkResponse(BaseModel):
    watermarked_output: str
    watermark_id: str
    watermark_type: str
    confidence: float


class MonitorRequest(BaseModel):
    session_id: str
    query: str
    source_ip: str
    user_id: str


class MonitorResponse(BaseModel):
    session_id: str
    risk_score: float
    alerts: list[dict]
    should_block: bool
    should_rate_limit: bool
    latency_ms: float


class FullDefenseRequest(BaseModel):
    session_id: str
    query: str
    output: str
    source_ip: str
    user_id: str


class FullDefenseResponse(BaseModel):
    protected_output: str
    risk_score: float
    alerts: list[dict]
    should_block: bool
    latency_ms: float


@router.post("/watermark", response_model=WatermarkResponse)
async def apply_watermark(
    request: WatermarkRequest,
    defense: ModelExtractionDefense = Depends(get_defense),
):
    """Apply an invisible watermark to model output."""
    result = defense.apply_watermark(request.output)
    return WatermarkResponse(
        watermarked_output=result.watermarked_output,
        watermark_id=result.watermark_id,
        watermark_type=result.watermark_type,
        confidence=result.confidence,
    )


@router.post("/monitor", response_model=MonitorResponse)
async def monitor_query(
    request: MonitorRequest,
    defense: ModelExtractionDefense = Depends(get_defense),
):
    """Monitor a query for extraction patterns."""
    result = defense.monitor_query(
        request.session_id, request.query, request.source_ip, request.user_id
    )
    return MonitorResponse(
        session_id=result.session_id,
        risk_score=result.risk_score,
        alerts=[a.__dict__ for a in result.alerts],
        should_block=result.should_block,
        should_rate_limit=result.should_rate_limit,
        latency_ms=result.latency_ms,
    )


@router.post("/full-defense", response_model=FullDefenseResponse)
async def full_defense(
    request: FullDefenseRequest,
    defense: ModelExtractionDefense = Depends(get_defense),
):
    """Run the full defense pipeline: monitor + watermark + perturb."""
    protected_output, monitor = defense.full_defense(
        request.session_id, request.query, request.output,
        request.source_ip, request.user_id,
    )
    return FullDefenseResponse(
        protected_output=protected_output,
        risk_score=monitor.risk_score,
        alerts=[a.__dict__ for a in monitor.alerts],
        should_block=monitor.should_block,
        latency_ms=monitor.latency_ms,
    )


@router.get("/health")
async def health_check():
    return {"module": "model_extraction_defense", "status": "healthy", "version": "1.0.0"}