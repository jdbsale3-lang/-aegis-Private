# AEGIS - Security Middleware
# API key validation, rate limiting, security headers

import time
import hmac
import logging
from typing import Callable
from collections import defaultdict

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import settings

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter. Replace with Redis in production."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds

        # Clean old entries
        self.requests[key] = [t for t in self.requests[key] if t > window_start]

        # Check limit
        if len(self.requests[key]) >= self.max_requests:
            return True

        self.requests[key].append(now)
        return False


# Global rate limiter instances
_general_limiter = RateLimiter(max_requests=100, window_seconds=60)


def validate_api_key(request: Request) -> str:
    """Validate the API key from headers.

    In production, this should check against the database for tenant-specific keys.
    """
    api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")

    if not api_key and settings.ENVIRONMENT == "production":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide via x-api-key header.",
        )

    # In production, validate against database
    if settings.API_KEY and api_key:
        if not hmac.compare_digest(api_key, settings.API_KEY):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid API key.",
            )

    return api_key or "dev-mode"


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware: rate limiting + security headers."""

    async def dispatch(self, request: Request, call_next: Callable):
        # Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        if _general_limiter.is_limited(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": "60"},
            )

        # Process the request
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-AEGIS-Protected"] = "true"

        # Remove server header that leaks version info
        if "server" in response.headers:
            del response.headers["server"]

        # CSP in production
        if settings.ENVIRONMENT == "production":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "object-src 'none'; "
                "frame-ancestors 'none'"
            )

        return response