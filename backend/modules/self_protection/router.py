# AEGIS-on-itself: Self-Protection - API Router

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from modules.self_protection.watcher import AEGISSelfProtection

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/self-protection", tags=["self-protection"])

_watcher: AEGISSelfProtection | None = None


def get_watcher() -> AEGISSelfProtection:
    global _watcher
    if _watcher is None:
        _watcher = AEGISSelfProtection()
    return _watcher


class UpdateRuntimeRequest(BaseModel):
    check_name: str
    is_active: bool


@router.post("/check")
async def run_full_check(watcher: AEGISSelfProtection = Depends(get_watcher)):
    """Run a complete self-protection integrity check across all components."""
    report = watcher.run_full_check()
    return {
        "report_id": report.report_id,
        "timestamp": report.timestamp,
        "overall_score": report.overall_score,
        "status": report.status,
        "checks": [
            {
                "check_id": c.check_id,
                "component": c.component,
                "status": c.status,
                "findings": c.findings,
                "score": c.score,
                "latency_ms": c.latency_ms,
            }
            for c in report.checks
        ],
        "active_threats": report.active_threats,
        "recommendations": report.recommendations,
    }


@router.post("/runtime-state")
async def update_runtime_state(
    request: UpdateRuntimeRequest,
    watcher: AEGISSelfProtection = Depends(get_watcher),
):
    """Update the runtime state of a security check."""
    watcher.update_runtime_state(request.check_name, request.is_active)
    return {
        "status": "updated",
        "check_name": request.check_name,
        "is_active": request.is_active,
    }


@router.post("/reset-baseline")
async def reset_baseline(watcher: AEGISSelfProtection = Depends(get_watcher)):
    """Reset file hash baselines after a legitimate deploy."""
    watcher.reset_baseline()
    return {"status": "baselines reset"}


@router.get("/health")
async def health_check():
    return {"module": "self_protection", "status": "healthy", "version": "1.0.0"}
