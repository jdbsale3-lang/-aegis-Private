# AEGIS Module 4: RAG Security - API Router

import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field

from modules.rag_security.engine import RAGSecurityEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rag", tags=["rag-security"])

_engine: Optional[RAGSecurityEngine] = None


def get_engine() -> RAGSecurityEngine:
    global _engine
    if _engine is None:
        _engine = RAGSecurityEngine()
    return _engine


class ScanDocumentRequest(BaseModel):
    document_id: str = Field(..., min_length=1, max_length=255)
    text: str = Field(..., min_length=1, max_length=100000)


class ScanDocumentResponse(BaseModel):
    document_id: str
    safe_to_embed: bool
    risk_score: float
    threats_found: list[dict]
    chunk_count: int
    latency_ms: float


class TraceQueryRequest(BaseModel):
    query_id: str = Field(..., min_length=1, max_length=255)
    query: str = Field(..., min_length=1)
    retrieved_chunks: list[dict]


class TraceQueryResponse(BaseModel):
    query_id: str
    query_hash: str
    anomaly_score: float
    poisoned_chunks: list[str]
    explanation: str
    latency_ms: float


@router.post("/scan", response_model=ScanDocumentResponse)
async def scan_document(
    request: ScanDocumentRequest,
    engine: RAGSecurityEngine = Depends(get_engine),
):
    """Layer 1: Scan a document for adversarial content before embedding into vector DB."""
    result = engine.scan_document(request.document_id, request.text)
    return ScanDocumentResponse(
        document_id=result.document_id,
        safe_to_embed=result.safe_to_embed,
        risk_score=result.risk_score,
        threats_found=result.threats_found,
        chunk_count=result.chunk_count,
        latency_ms=result.latency_ms,
    )


@router.post("/trace", response_model=TraceQueryResponse)
async def trace_query(
    request: TraceQueryRequest,
    engine: RAGSecurityEngine = Depends(get_engine),
):
    """Layer 2: Trace which documents influenced a response and flag anomalies."""
    result = engine.trace_query(request.query_id, request.query, request.retrieved_chunks)
    return TraceQueryResponse(
        query_id=result.query_id,
        query_hash=result.query_hash,
        anomaly_score=result.anomaly_score,
        poisoned_chunks=result.poisoned_chunks,
        explanation=result.explanation,
        latency_ms=result.latency_ms,
    )


@router.post("/batch-scan")
async def batch_scan(
    documents: list[dict],
    engine: RAGSecurityEngine = Depends(get_engine),
):
    """Batch scan multiple documents."""
    docs = [(d["document_id"], d["text"]) for d in documents]
    results = engine.batch_scan_documents(docs)
    return {"results": [r.__dict__ for r in results], "count": len(results)}


@router.get("/health")
async def health_check():
    return {"module": "rag_security", "status": "healthy", "version": "1.0.0"}