# AEGIS Lightweight API Server
# Standalone server - no database required
# All 8 modules accessible via HTTP API

import logging
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from modules.prompt_defense.router import router as prompt_defense_router
from modules.agent_auth.router import router as agent_auth_router
from modules.rag_security.router import router as rag_security_router
from modules.supply_chain.router import router as supply_chain_router
from modules.model_extraction.router import router as extraction_router
from modules.vector_security.router import router as vector_security_router
from modules.self_protection.router import router as self_protection_router
from modules.advanced_defenses.router import router as advanced_defenses_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("aegis-api")

app = FastAPI(
    title="AEGIS - AI Security & Guardian Intelligence System",
    description="Unified AI security platform. All 8 modules accessible via API.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


@app.get("/")
async def root():
    return {
        "service": "AEGIS AI Security Platform",
        "version": "1.0.0",
        "owner": "ZEUS AI Intelligence",
        "founder": "Darren Birch",
        "ip": "JDB Sales",
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
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting AEGIS API server on port {port}")
    uvicorn.run("api_server:app", host="0.0.0.0", port=port, log_level="info")