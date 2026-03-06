"""
FastAPI application factory for AZSploitMapper.

Security features:
- Authentication middleware (API key or Entra ID OAuth2)
- Security headers (CSP, X-Frame-Options, HSTS, etc.)
- Request size limits
- Scan result eviction (max 20 stored scans)
- No subprocess calls or external command execution
- Audit logging for all security events
"""

from __future__ import annotations

import os
import secrets
from collections import OrderedDict
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from azsploitmapper.api.routes import (
    scans_router, resources_router, paths_router,
    findings_router, compliance_router,
)
from azsploitmapper.auth.entra import EntraAuthConfig, AuthMiddleware, create_auth_routes
from azsploitmapper.db.database import get_engine, load_all_scans
from azsploitmapper.logging_config import setup_logging, get_audit_logger

# Maximum number of scan results kept in memory
MAX_STORED_SCANS = 20

logger = setup_logging()
audit = get_audit_logger()


class LimitedScanStore(OrderedDict):
    """
    Ordered dict that evicts the oldest scan when MAX_STORED_SCANS is exceeded.

    This prevents unbounded memory growth from repeated scans.
    """

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        while len(self) > MAX_STORED_SCANS:
            oldest_key, _ = self.popitem(last=False)
            logger.info("Evicted oldest scan from memory: %s", oldest_key[:8])


def create_app() -> FastAPI:
    """
    Build and configure the FastAPI application with security hardening.

    Returns a fully configured FastAPI app ready to serve.
    """
    app = FastAPI(
        title="AZSploitMapper",
        description="Azure Attack Path Visualizer",
        version="0.2.0",
        # Disable automatic docs in production to reduce attack surface
        docs_url=None if os.getenv("AZSPLOITMAPPER_API_KEY") else "/docs",
        redoc_url=None,
    )

    # --- CORS configuration (restrictive by default) ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],  # No cross-origin requests allowed
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # --- Authentication middleware ---
    auth_config = EntraAuthConfig()
    app.add_middleware(AuthMiddleware, auth_config=auth_config)

    # --- Static files and templates ---
    pkg_dir = Path(__file__).resolve().parent.parent
    static_dir = pkg_dir / "web" / "static"
    templates_dir = pkg_dir / "web" / "templates"

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    templates = Jinja2Templates(directory=str(templates_dir))
    app.state.templates = templates
    app.state.scan_results = LimitedScanStore()

    # Initialize database and load saved scans
    db_engine = get_engine()
    app.state.db_engine = db_engine
    saved_scans = load_all_scans(db_engine)
    for sid, sdata in saved_scans.items():
        app.state.scan_results[sid] = sdata

    # Generate a CSP nonce for inline scripts (rotated per app instance)
    app.state.csp_nonce = secrets.token_urlsafe(16)

    # --- Include routers ---
    app.include_router(create_auth_routes(auth_config))
    app.include_router(scans_router)
    app.include_router(resources_router)
    app.include_router(paths_router)
    app.include_router(findings_router)
    app.include_router(compliance_router)

    # --- Security headers middleware ---
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next) -> Response:
        """Add security headers to every response."""
        response = await call_next(request)

        nonce = app.state.csp_nonce

        # Content Security Policy -- restrict script sources
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"img-src 'self' data:; "
            f"connect-src 'self'; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self' https://login.microsoftonline.com"
        )

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS protection in older browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy -- don't leak URLs to external sites
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy -- disable unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # HSTS -- enforce HTTPS for 1 year
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Remove server header to avoid fingerprinting
        if "server" in response.headers:
            del response.headers["server"]

        return response

    # --- Helper functions ---
    def _ctx(request: Request, **extra) -> dict:
        """Build Jinja2 template context with common variables."""
        ctx = {
            "request": request,
            "csp_nonce": app.state.csp_nonce,
        }
        user_email = getattr(request.state, "user_email", None)
        if user_email:
            ctx["user_email"] = user_email
        ctx.update(extra)
        return ctx

    def _latest_scan_id() -> str | None:
        """Return the most recent scan ID or None."""
        results = app.state.scan_results
        if results:
            return list(results.keys())[-1]
        return None

    # --- Health check (no auth required - exempt in middleware) ---
    @app.get("/api/health")
    def health_check():
        """Minimal health check -- returns only status."""
        return {"status": "ok"}

    # --- Page routes ---
    @app.get("/")
    def root_redirect():
        return RedirectResponse(url="/dashboard", status_code=302)

    @app.get("/dashboard")
    def dashboard_page(request: Request):
        configured_sub = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        configured_tenant = os.getenv("AZURE_TENANT_ID", "")
        configured_client = os.getenv("AZURE_CLIENT_ID", "")
        return templates.TemplateResponse(
            "dashboard.html", _ctx(
                request,
                active_page="dashboard",
                configured_subscription_id=configured_sub,
                configured_tenant_id=configured_tenant,
                configured_client_id=configured_client,
            )
        )

    # Navigation shortcut routes -- redirect to latest scan or dashboard
    @app.get("/graph")
    def graph_redirect():
        sid = _latest_scan_id()
        return RedirectResponse(
            url=f"/graph/{sid}" if sid else "/dashboard", status_code=302
        )

    @app.get("/findings")
    def findings_redirect():
        sid = _latest_scan_id()
        return RedirectResponse(
            url=f"/findings/{sid}" if sid else "/dashboard", status_code=302
        )

    @app.get("/compliance")
    def compliance_redirect():
        sid = _latest_scan_id()
        return RedirectResponse(
            url=f"/compliance/{sid}" if sid else "/dashboard", status_code=302
        )

    @app.get("/inventory")
    def inventory_redirect():
        sid = _latest_scan_id()
        return RedirectResponse(
            url=f"/inventory/{sid}" if sid else "/dashboard", status_code=302
        )

    @app.get("/graph/{scan_id}")
    def graph_page(request: Request, scan_id: str):
        if scan_id not in app.state.scan_results:
            return templates.TemplateResponse(
                "error.html",
                _ctx(request, message="Scan not found"),
                status_code=404,
            )
        return templates.TemplateResponse(
            "graph.html",
            _ctx(request, scan_id=scan_id, active_page="graph"),
        )

    @app.get("/findings/{scan_id}")
    def findings_page(request: Request, scan_id: str):
        if scan_id not in app.state.scan_results:
            return templates.TemplateResponse(
                "error.html",
                _ctx(request, message="Scan not found"),
                status_code=404,
            )
        return templates.TemplateResponse(
            "findings.html",
            _ctx(request, scan_id=scan_id, active_page="findings"),
        )

    @app.get("/compliance/{scan_id}")
    def compliance_page(request: Request, scan_id: str):
        if scan_id not in app.state.scan_results:
            return templates.TemplateResponse(
                "error.html",
                _ctx(request, message="Scan not found"),
                status_code=404,
            )
        return templates.TemplateResponse(
            "compliance.html",
            _ctx(request, scan_id=scan_id, active_page="compliance"),
        )

    @app.get("/inventory/{scan_id}")
    def inventory_page(request: Request, scan_id: str):
        if scan_id not in app.state.scan_results:
            return templates.TemplateResponse(
                "error.html",
                _ctx(request, message="Scan not found"),
                status_code=404,
            )
        return templates.TemplateResponse(
            "inventory.html",
            _ctx(request, scan_id=scan_id, active_page="inventory"),
        )

    audit.info("AZSploitMapper app initialized")
    return app
