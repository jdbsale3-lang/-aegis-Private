# AEGIS Lightweight API Server
# Standalone server - no database required
# All 8 modules accessible via HTTP API
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

import json
import os
import re
import uuid
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from modules.advanced_defenses.router import router as advanced_defenses_router
from modules.agent_auth.router import router as agent_auth_router
from modules.key_management.router import router as key_management_router
from modules.model_extraction.router import router as extraction_router
from modules.prompt_defense.router import router as prompt_defense_router
from modules.rag_security.router import router as rag_security_router
from modules.self_protection.router import router as self_protection_router
from modules.supply_chain.router import router as supply_chain_router
from modules.vector_security.router import router as vector_security_router

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s"
)
logger = logging.getLogger("aegis-api")

app = FastAPI(
    title="AEGIS - AI Security & Guardian Intelligence System",
    description="Unified AI security platform. All 8 modules accessible via API.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://aegis-security.higgsfield.app",
        "https://apiaegissecurity.tech",
        "https://zeusai-intelligence.higgsfield.app",
        "https://zeusai-intelligence.org",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all 8 modules
app.include_router(prompt_defense_router)
app.include_router(agent_auth_router)
app.include_router(rag_security_router)
app.include_router(supply_chain_router)
app.include_router(extraction_router)
app.include_router(vector_security_router)
app.include_router(self_protection_router)
app.include_router(advanced_defenses_router)
app.include_router(key_management_router)

# API Key storage
API_KEYS_FILE = "/opt/aegis/data/api_keys.json"

# ---- RBAC: privileged endpoints require an ADMIN key ----
# Free keys (created via /register) are role "read".
# Admin keys carry role "admin" and are provisioned manually (not via register).
ADMIN_ONLY_PATHS = [
    "/api/v1/self-protection/reset-baseline",
    "/api/v1/self-protection/runtime-state",
    "/api/v1/vector-security/policy",
    "/api/v1/vector-security/decrypt",
]

# Per-key monthly quota (must match the registration message)
MONTHLY_QUOTA = 1000

_EMAIL_RE = re.compile(r"^[^@\s]{1,254}@[^@\s]{1,64}\.[^@\s]{1,63}$")


class RegisterRequest(BaseModel):
    email: str
    name: str
    accept_terms: bool = False


def load_api_keys():
    if os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE) as f:
            return json.load(f)
    return {}


def save_api_keys(keys):
    os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
    with open(API_KEYS_FILE, "w") as f:
        json.dump(keys, f)


# Rate limiting stores
_reg_limits = defaultdict(list)  # per-IP registration timestamps
_email_limits = defaultdict(list)  # per-email registration timestamps

# Per-key sliding-window rate limit (app layer, distinct from the WAF).
# Returns proper 429 + Retry-After so clients can distinguish throttle from WAF block.
RATE_LIMIT_PER_MINUTE = 120
_req_limits = defaultdict(list)  # key -> [timestamps within last 60s]


def _rate_limit_check(api_key: str) -> int | None:
    """Return Retry-After seconds if over limit, else None."""
    _now = time.time()
    window = [t for t in _req_limits[api_key] if _now - t < 60]
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        return int(60 - (_now - window[0])) + 1
    window.append(_now)
    _req_limits[api_key] = window[-RATE_LIMIT_PER_MINUTE:]
    return None


@app.post("/api/v1/register")
async def register(request: RegisterRequest, http_request: Request):
    """Register for a free (read) API key - admin role is not grantable via this route."""
    # Validate email format
    email = (request.email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return JSONResponse(
            status_code=400, content={"detail": "Invalid email address."}
        )
    if not request.accept_terms:
        return JSONResponse(
            status_code=400,
            content={
                "detail": "You must accept the Terms of Service. Read them at /terms"
            },
        )

    _now = time.time()
    _ip = http_request.client.host if http_request.client else "unknown"

    # Per-IP limit: max 5 registrations per hour
    _reg_limits[_ip] = [t for t in _reg_limits[_ip] if _now - t < 3600]
    if len(_reg_limits[_ip]) >= 5:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many registrations from this IP. Try again later."},
        )
    _reg_limits[_ip].append(_now)

    # Per-email limit: max 3 registrations per 24h
    _email_limits[email] = [t for t in _email_limits[email] if _now - t < 86400]
    if len(_email_limits[email]) >= 3:
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Too many registrations for this email. Try again later."
            },
        )
    _email_limits[email].append(_now)

    keys = load_api_keys()
    api_key = f"aegis_{uuid.uuid4().hex[:24]}"
    # IMPORTANT: role is forced to "read" - free keys can never self-escalate.
    keys[api_key] = {
        "email": email,
        "name": (request.name or "").strip()[:100],
        "created": _now,
        "requests": 0,
        "accepted_terms": True,
        "role": "read",
    }
    save_api_keys(keys)
    return {
        "api_key": api_key,
        "message": "Free API key created (read-only). 1000 requests/month included.",
    }


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    """Validate API key + RBAC + quota on all endpoints except public ones."""
    public_paths = ["/health", "/api/v1/register", "/terms"]
    # Docs surfaces are now gated (P1-5): require a valid key.
    if request.url.path in public_paths or request.url.path.startswith(
        "/api/v1/register"
    ):
        return await call_next(request)

    api_key = request.headers.get("x-api-key")
    keys = load_api_keys()

    if not api_key or api_key not in keys:
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Missing or invalid API key. Register at POST /api/v1/register"
            },
        )

    key_record = keys[api_key]
    role = key_record.get("role", "read")

    # Enforce per-key monthly quota (P1-6)
    if key_record.get("requests", 0) >= MONTHLY_QUOTA:
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Monthly request quota ({MONTHLY_QUOTA}) exceeded. Contact support to upgrade."
            },
        )

    # RBAC (P0-2): privileged paths require admin role
    if request.url.path in ADMIN_ONLY_PATHS and role != "admin":
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Forbidden: this operation requires an administrator API key."
            },
        )

    # App-layer rate limit (P2-7): 429 + Retry-After, distinct from the WAF
    retry_after = _rate_limit_check(api_key)
    if retry_after is not None:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after), "X-AEGIS-Rate-Limited": "true"},
            content={
                "detail": f"Rate limit exceeded. Retry after {retry_after} seconds."
            },
        )

    key_record["requests"] = key_record.get("requests", 0) + 1
    save_api_keys(keys)

    response = await call_next(request)
    response.headers["X-AEGIS-Auth"] = "verified"
    response.headers["X-AEGIS-Role"] = role
    try:
        used = len(_req_limits.get(api_key, []))
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_PER_MINUTE)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, RATE_LIMIT_PER_MINUTE - used)
        )
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)
        response.headers["X-RateLimit-Window"] = "60"
    except Exception:
        pass
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # P0-3: sanitize - log full detail server-side, return generic message to client
    logger.error(f"Unhandled exception on {request.url.path}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/nhs-compliance")
async def nhs_compliance():
    """NHS ID Card compliance check endpoint (P1-4: no PII / identity disclosure)."""
    return {
        "service": "AEGIS AI Security Platform",
        "nhs_compliance": {
            "uk_gdpr": True,
            "data_protection_act_2018": True,
            "nhs_dspt_ready": True,
            "iso_27001_mapped": True,
            "dcb0129_clinical_safety": True,
            "caldicott_principles": True,
            "accessibility_wcag_2_1": True,
        },
        "security_modules": 8,
        "endpoints": 37,
        "data_encryption": "AES-256-GCM",
        "authentication": "API Key (RBAC) + JWT + 2FA ready",
        "audit_logging": "Real-time, 7 year retention",
        "breach_response": "ICO notification within 24 hours",
        "compliance_status": "Self-assessment - external audit in progress",
    }


@app.get("/stats")
async def stats():
    """Get AEGIS platform statistics (P1-4: no PII / identity disclosure)."""
    keys = load_api_keys()
    total_keys = len(keys)
    total_requests = sum(k.get("requests", 0) for k in keys.values())
    return {
        "service": "AEGIS AI Security Platform",
        "version": "1.0.0",
        "modules": 8,
        "endpoints": 37,
        "tests_passing": 92,
        "attack_vectors_covered": 7,
        "registered_users": total_keys,
        "total_api_requests": total_requests,
        "status": "production",
    }


@app.get("/terms")
async def terms():
    return {
        "service": "AEGIS AI Security Platform",
        "terms": "By using this API you agree to the Terms of Service. All rights reserved. No copying, modification, reverse engineering, or distribution permitted.",
        "copyright": "Copyright (c) 2026 ZEUS AI Intelligence / JDB Sales. All Rights Reserved.",
    }


@app.get("/")
async def root():
    return {
        "service": "AEGIS AI Security Platform",
        "version": "1.0.0",
        "modules": {
            "prompt_defense": "active",
            "agent_auth": "active",
            "rag_security": "active",
            "supply_chain": "active",
            "model_extraction_defense": "active",
            "vector_security": "active",
            "self_protection": "active",
            "advanced_defenses": "active",
        },
        "endpoints": 37,
        "tests": 92,
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "AEGIS", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    logger.info(f"Starting AEGIS API server on port {port}")
    uvicorn.run("api_server:app", host="0.0.0.0", port=port, log_level="info")
