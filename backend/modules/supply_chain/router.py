# AEGIS Module 5: Supply Chain Scanner - API Router

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from modules.supply_chain.scanner import SupplyChainScanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/supply-chain", tags=["supply-chain"])

_scanner: SupplyChainScanner | None = None


def get_scanner() -> SupplyChainScanner:
    global _scanner
    if _scanner is None:
        _scanner = SupplyChainScanner()
    return _scanner


class ScanModelRequest(BaseModel):
    file_path: str
    metadata: dict | None = None
    weight_names: list[str] | None = None


class ScanPackageRequest(BaseModel):
    name: str
    version: str
    requirements_file: str | None = None


class ScanRequirementsRequest(BaseModel):
    requirements_text: str


@router.post("/model")
async def scan_model(
    request: ScanModelRequest,
    scanner: SupplyChainScanner = Depends(get_scanner),
):
    """Scan a model file for supply chain risks (serialization, backdoors, metadata)."""
    result = scanner.scan_model(
        request.file_path, request.metadata, request.weight_names
    )
    return {
        "target": result.target,
        "target_type": result.target_type,
        "findings": [f.__dict__ for f in result.findings],
        "risk_score": result.risk_score,
        "passed": result.passed,
        "summary": result.summary,
        "latency_ms": result.latency_ms,
    }


@router.post("/package")
async def scan_package(
    request: ScanPackageRequest,
    scanner: SupplyChainScanner = Depends(get_scanner),
):
    """Scan a package for known CVEs and supply chain risks."""
    result = scanner.scan_package(
        request.name, request.version, request.requirements_file
    )
    return {
        "target": result.target,
        "target_type": result.target_type,
        "findings": [f.__dict__ for f in result.findings],
        "risk_score": result.risk_score,
        "passed": result.passed,
        "summary": result.summary,
        "latency_ms": result.latency_ms,
    }


@router.post("/requirements")
async def scan_requirements(
    request: ScanRequirementsRequest,
    scanner: SupplyChainScanner = Depends(get_scanner),
):
    """Scan a requirements.txt file for dependency risks."""
    result = scanner.scan_requirements(request.requirements_text)
    return {
        "target": result.target,
        "target_type": result.target_type,
        "findings": [f.__dict__ for f in result.findings],
        "risk_score": result.risk_score,
        "passed": result.passed,
        "summary": result.summary,
        "latency_ms": result.latency_ms,
    }


@router.get("/health")
async def health_check():
    return {"module": "supply_chain", "status": "healthy", "version": "1.0.0"}
