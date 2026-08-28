# AEGIS Backend - Main Application Entry Point
# Unified API server for Modules 1, 2, and shared infrastructure

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.database import close_db, init_db
from core.security import SecurityMiddleware
from modules.advanced_defenses.router import router as advanced_defenses_router
from modules.agent_auth.router import router as agent_auth_router
from modules.key_management.router import router as key_management_router
from modules.model_extraction.router import router as extraction_router
from modules.prompt_defense.router import router as prompt_defense_router
from modules.rag_security.router import router as rag_security_router
from modules.self_protection.router import router as self_protection_router
from modules.supply_chain.router import router as supply_chain_router
from modules.vector_security.router import router as vector_security_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup and shutdown."""
    logger.info(f"Starting {settings.APP_NAME} - Environment: {settings.ENVIRONMENT}")
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization skipped (first run?): {e}")

    yield

    # Shutdown
    await close_db()
    logger.info("Application shutdown complete")


app = FastAPI(
    title="AEGIS - AI Security & Guardian Intelligence System",
    description="Unified AI security platform protecting LLM applications, AI agents, and infrastructure.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security middleware (rate limiting + security headers)
app.add_middleware(SecurityMiddleware)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "error": str(exc) if settings.DEBUG else "An unexpected error occurred",
        },
    )


# Register module routers
app.include_router(prompt_defense_router)
app.include_router(agent_auth_router)
app.include_router(rag_security_router)
app.include_router(supply_chain_router)
app.include_router(extraction_router)
app.include_router(vector_security_router)
app.include_router(self_protection_router)
app.include_router(advanced_defenses_router)
app.include_router(key_management_router)


# Health check
@app.get("/health")
async def root_health():
    return {
        "service": "AEGIS",
        "version": "1.0.0",
        "status": "healthy",
        "modules": {
            "prompt_defense": "active",
            "agent_auth": "active",
            "rag_security": "active",
            "supply_chain": "active",
            "model_extraction_defense": "active",
            "vector_security": "active",
            "self_protection": "active",
            "advanced_defenses": "active",
            "mcp_gateway": "external",
        },
        "environment": settings.ENVIRONMENT,
    }


# Metrics endpoint (Prometheus)
@app.get("/metrics")
async def metrics():
    """Stub - wire Prometheus client for production."""
    return {"metrics": "Prometheus metrics endpoint - configure in production"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower(),
    )
