# -*- coding: utf-8 -*-
"""
Middleware y headers de seguridad para la aplicación.
"""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware para agregar headers de seguridad a todas las respuestas."""
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        
        # Prevenir MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevenir clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS Protection (legacy pero útil)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        
        # Cache control para datos sensibles
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        
        return response


def setup_security(app: FastAPI, allowed_origins: list[str] | None = None):
    """Configura todos los middlewares de seguridad."""
    
    # CORS - restrictivo por defecto
    if allowed_origins is None:
        allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
        max_age=600,  # Cache preflight por 10 minutos
    )
    
    # Headers de seguridad
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Rate limiting
    app.state.limiter = limiter
    
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return Response(
            content='{"detail": "Demasiadas solicitudes. Intente de nuevo en un minuto."}',
            status_code=429,
            media_type="application/json",
            headers={"Retry-After": "60"}
        )
