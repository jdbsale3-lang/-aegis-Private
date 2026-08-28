# AEGIS Module 1: Prompt Defense API Routes

import hashlib
import logging

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from core.config import settings
from modules.prompt_defense.classifier import PromptClassifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/prompt", tags=["prompt-defense"])

# Singleton classifier instance
_classifier: PromptClassifier | None = None


def get_classifier() -> PromptClassifier:
    global _classifier
    if _classifier is None:
        _classifier = PromptClassifier(
            model_path=settings.PROMPT_ENSEMBLE_MODEL_PATH,
            signature_path=settings.PROMPT_SIGNATURE_PATH,
        )
    return _classifier


# --- Request/Response Models ---


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32000)
    context: dict | None = Field(default=None, description="Application context")
    mode: str = Field(default="block", pattern="^(block|flag|monitor)$")


class ClassifierScores(BaseModel):
    semantic: float
    syntactic: float
    behavioral: float


class AnalyzeResponse(BaseModel):
    verdict: str  # safe | suspicious | malicious
    score: float
    classifier_scores: ClassifierScores
    triggered_rules: list[str]
    request_hash: str
    latency_ms: float
    action: str  # allow | flag | block


class BatchAnalyzeRequest(BaseModel):
    prompts: list[str] = Field(..., min_length=1, max_length=100)
    context: dict | None = None
    mode: str = Field(default="block", pattern="^(block|flag|monitor)$")


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]
    total_time_ms: float


class SignatureModel(BaseModel):
    pattern: str
    category: str
    severity: str = "medium"
    description: str | None = None
    reference: str | None = None


# --- Routes ---


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(
    request: AnalyzeRequest,
    x_api_key: str | None = Header(None),
    classifier: PromptClassifier = Depends(get_classifier),
):
    """Analyze a single prompt for injection attacks using the ensemble classifier."""
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")

    result = classifier.analyze(request.prompt)
    request_hash = hashlib.sha256(request.prompt.encode()).hexdigest()[:16]

    # Determine action based on mode and verdict
    if request.mode == "monitor":
        action = "allow"
    elif request.mode == "flag" and result.verdict == "malicious":
        action = "block"
    elif request.mode == "flag" and result.verdict == "suspicious":
        action = "flag"
    elif request.mode == "block":
        action = {"safe": "allow", "suspicious": "flag", "malicious": "block"}[
            result.verdict
        ]
    else:
        action = "allow"

    return AnalyzeResponse(
        verdict=result.verdict,
        score=result.ensemble_score,
        classifier_scores=ClassifierScores(
            semantic=result.semantic_score,
            syntactic=result.syntactic_score,
            behavioral=result.behavioral_score,
        ),
        triggered_rules=result.triggered_rules,
        request_hash=request_hash,
        latency_ms=result.latency_ms,
        action=action,
    )


@router.post("/batch", response_model=BatchAnalyzeResponse)
async def batch_analyze(
    request: BatchAnalyzeRequest,
    classifier: PromptClassifier = Depends(get_classifier),
):
    """Batch analyze multiple prompts."""
    import time

    start = time.time()

    results = []
    for prompt in request.prompts:
        result = classifier.analyze(prompt)
        request_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        action = {"safe": "allow", "suspicious": "flag", "malicious": "block"}[
            result.verdict
        ]
        results.append(
            AnalyzeResponse(
                verdict=result.verdict,
                score=result.ensemble_score,
                classifier_scores=ClassifierScores(
                    semantic=result.semantic_score,
                    syntactic=result.syntactic_score,
                    behavioral=result.behavioral_score,
                ),
                triggered_rules=result.triggered_rules,
                request_hash=request_hash,
                latency_ms=result.latency_ms,
                action=action,
            )
        )

    total_time = (time.time() - start) * 1000
    return BatchAnalyzeResponse(results=results, total_time_ms=round(total_time, 2))


@router.get("/signatures")
async def list_signatures(classifier: PromptClassifier = Depends(get_classifier)):
    """List all active attack signatures."""
    return {
        "signatures": classifier.attack_signatures,
        "count": len(classifier.attack_signatures),
    }


@router.get("/health")
async def health_check():
    """Module health check."""
    return {"module": "prompt_defense", "status": "healthy", "version": "1.0.0"}
