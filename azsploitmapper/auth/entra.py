"""
Authentication middleware and routes for AZSploitMapper.

Supports three authentication modes (checked in order):
1. API Key -- via "Authorization: Api-Key <key>" header
2. Entra ID (Azure AD) OAuth2 -- browser-based Microsoft sign-in
3. Session cookie -- for returning browser users after OAuth login

Security features:
- Sessions have TTL and max count limits
- Cookies are HttpOnly, Secure, and SameSite=Lax
- Auth flows expire after 10 minutes
- API keys are validated via constant-time comparison
- All auth events are logged to the audit trail
"""

import os
import secrets
import time

import httpx
import msal
from fastapi import APIRouter, Form, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse

from azsploitmapper.auth.api_keys import validate_api_key, validate_env_api_key
from azsploitmapper.logging_config import get_audit_logger

audit = get_audit_logger()

# Session configuration from environment
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", "28800"))  # 8 hours
SESSION_MAX_COUNT = int(os.getenv("SESSION_MAX_COUNT", "100"))
AUTH_FLOW_TTL = 600  # 10 minutes for OAuth flows


class EntraAuthConfig:
    """Configuration for Entra ID authentication."""

    def __init__(self):
        # Entra ID (OAuth2) settings -- optional
        self.client_id = os.getenv("ENTRA_CLIENT_ID", "")
        self.client_secret = os.getenv("ENTRA_CLIENT_SECRET", "")
        self.tenant_id = os.getenv("ENTRA_TENANT_ID", "")
        self.redirect_uri = os.getenv(
            "AUTH_REDIRECT_URI", "https://localhost:8443/auth/callback"
        )
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.scope = ["User.Read"]
        self.entra_enabled = bool(
            self.client_id and self.client_secret and self.tenant_id
        )

        # API key auth -- always available if a key is configured
        self.api_key_enabled = bool(os.getenv("AZSPLOITMAPPER_API_KEY", ""))

    def get_msal_app(self) -> msal.ConfidentialClientApplication:
        """Build a confidential MSAL client for the auth code flow."""
        return msal.ConfidentialClientApplication(
            self.client_id,
            authority=self.authority,
            client_credential=self.client_secret,
        )


class SessionStore:
    """
    In-memory session store with TTL and max count enforcement.

    Each session has a creation timestamp. Sessions older than
    SESSION_MAX_AGE are automatically expired. The total number
    of sessions is capped at SESSION_MAX_COUNT to prevent memory
    exhaustion attacks.
    """

    def __init__(self):
        self._sessions: dict[str, dict] = {}

    def create(self, email: str, name: str = "") -> str:
        """Create a new session and return the session token."""
        # Evict expired sessions first
        self._evict_expired()

        # Enforce max session count
        if len(self._sessions) >= SESSION_MAX_COUNT:
            # Remove oldest session
            oldest_key = min(
                self._sessions, key=lambda k: self._sessions[k]["created_at"]
            )
            del self._sessions[oldest_key]
            audit.warning("Session evicted (max count reached): %s", oldest_key[:8])

        token = secrets.token_urlsafe(32)
        self._sessions[token] = {
            "email": email,
            "name": name,
            "created_at": time.time(),
        }
        return token

    def get(self, token: str) -> dict | None:
        """Get session data if token is valid and not expired."""
        if not token or token not in self._sessions:
            return None

        session = self._sessions[token]
        age = time.time() - session["created_at"]
        if age > SESSION_MAX_AGE:
            del self._sessions[token]
            return None

        return session

    def delete(self, token: str):
        """Delete a session (logout)."""
        self._sessions.pop(token, None)

    def _evict_expired(self):
        """Remove all expired sessions."""
        now = time.time()
        expired = [
            k for k, v in self._sessions.items()
            if now - v["created_at"] > SESSION_MAX_AGE
        ]
        for k in expired:
            del self._sessions[k]


class AuthFlowStore:
    """
    Temporary storage for in-progress OAuth authorization code flows.

    Flows expire after AUTH_FLOW_TTL seconds to prevent stale state
    accumulation and replay attacks.
    """

    def __init__(self):
        self._flows: dict[str, dict] = {}

    def store(self, state: str, flow: dict):
        """Store an auth flow, evicting expired ones first."""
        self._evict_expired()
        flow["_created_at"] = time.time()
        self._flows[state] = flow

    def pop(self, state: str) -> dict | None:
        """Retrieve and remove an auth flow by state parameter."""
        flow = self._flows.pop(state, None)
        if flow is None:
            return None
        age = time.time() - flow.get("_created_at", 0)
        if age > AUTH_FLOW_TTL:
            audit.warning("Expired OAuth flow used: state=%s age=%ds", state[:8], age)
            return None
        return flow

    def _evict_expired(self):
        """Remove flows older than AUTH_FLOW_TTL."""
        now = time.time()
        expired = [
            k for k, v in self._flows.items()
            if now - v.get("_created_at", 0) > AUTH_FLOW_TTL
        ]
        for k in expired:
            del self._flows[k]


# Module-level stores (shared across requests within one process)
_sessions = SessionStore()
_auth_flows = AuthFlowStore()


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, checking X-Forwarded-For header."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces authentication on all requests.

    Authentication is checked in this order:
    1. API Key in Authorization header (for API/CLI clients)
    2. Session cookie (for browser users after OAuth login)

    If no valid auth is found, browser requests redirect to login page,
    API requests get a 401 JSON response.
    """

    EXEMPT_PATHS = {
        "/auth/login",
        "/auth/login-key",
        "/auth/login-entra",
        "/auth/callback",
        "/auth/logout",
        "/api/health",
        "/static",
    }

    def __init__(self, app, auth_config: EntraAuthConfig):
        super().__init__(app)
        self.auth_config = auth_config

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        client_ip = _get_client_ip(request)

        # Allow exempt paths without authentication
        for exempt in self.EXEMPT_PATHS:
            if path.startswith(exempt):
                return await call_next(request)

        # --- Check 1: API Key authentication ---
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Api-Key "):
            api_key = auth_header[8:].strip()
            # Try environment variable key first (simple mode)
            if validate_env_api_key(api_key):
                request.state.user_email = "api-key-user"
                audit.info(
                    "API key auth (env): ip=%s path=%s",
                    client_ip, path,
                )
                return await call_next(request)

            # Try file-based key store
            key_record = validate_api_key(api_key)
            if key_record:
                request.state.user_email = f"api:{key_record['name']}"
                audit.info(
                    "API key auth: name=%s prefix=%s ip=%s path=%s",
                    key_record["name"], key_record["prefix"], client_ip, path,
                )
                return await call_next(request)

            # Invalid API key
            audit.warning(
                "Invalid API key: ip=%s path=%s",
                client_ip, path,
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired API key"},
            )

        # --- Check 2: Session cookie authentication ---
        session_token = request.cookies.get("azsploit_session")
        session = _sessions.get(session_token) if session_token else None
        if session:
            request.state.user_email = session["email"]
            return await call_next(request)

        # --- No valid authentication found ---
        audit.info("Unauthenticated request: ip=%s path=%s", client_ip, path)

        # For API endpoints return 401 JSON
        if path.startswith("/api/"):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required. Use Api-Key header or sign in via /auth/login"},
            )

        # For browser requests redirect to login
        return RedirectResponse(url="/auth/login")


def create_auth_routes(auth_config: EntraAuthConfig) -> APIRouter:
    """Create FastAPI router with authentication endpoints."""
    router = APIRouter(tags=["auth"])

    @router.get("/auth/login")
    def login(request: Request):
        """
        Login page logic:
        - If Entra ID is NOT configured and an API key IS set in .env,
          auto-create a session and redirect to dashboard (single-user mode).
        - If Entra ID IS configured, show login page with options.
        - If nothing is configured, show login page with API key form.
        """
        # Single-user auto-login: API key in env + no Entra = skip login form
        if not auth_config.entra_enabled and auth_config.api_key_enabled:
            client_ip = _get_client_ip(request)
            token = _sessions.create(email="admin", name="Local Admin")
            audit.info("Auto-login (single-user mode): ip=%s", client_ip)
            response = RedirectResponse(url="/dashboard", status_code=302)
            response.set_cookie(
                "azsploit_session",
                token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=SESSION_MAX_AGE,
            )
            return response

        templates = request.app.state.templates
        csp_nonce = getattr(request.app.state, "csp_nonce", "")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "csp_nonce": csp_nonce,
            "entra_enabled": auth_config.entra_enabled,
            "error": None,
        })

    @router.post("/auth/login-key")
    def login_with_api_key(request: Request, api_key: str = Form(...)):
        """Validate an API key submitted via the login form and create a session."""
        client_ip = _get_client_ip(request)
        templates = request.app.state.templates
        csp_nonce = getattr(request.app.state, "csp_nonce", "")

        # Validate the submitted API key
        user_label = None

        # Check environment variable key first
        if validate_env_api_key(api_key):
            user_label = "api-key-user"

        # Check file-based key store
        if not user_label:
            key_record = validate_api_key(api_key)
            if key_record:
                user_label = f"api:{key_record['name']}"

        if not user_label:
            audit.warning("Failed API key login: ip=%s", client_ip)
            return templates.TemplateResponse("login.html", {
                "request": request,
                "csp_nonce": csp_nonce,
                "entra_enabled": auth_config.entra_enabled,
                "error": "Invalid or expired API key",
            }, status_code=401)

        # API key is valid -- create a session and set a cookie
        token = _sessions.create(email=user_label, name="API Key User")
        audit.info("API key login via browser: user=%s ip=%s", user_label, client_ip)

        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(
            "azsploit_session",
            token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=SESSION_MAX_AGE,
        )
        return response

    @router.get("/auth/login-entra")
    def login_entra(request: Request):
        """Start the Entra ID OAuth2 authorization code flow."""
        if not auth_config.entra_enabled:
            return RedirectResponse(url="/auth/login")

        app = auth_config.get_msal_app()
        flow = app.initiate_auth_code_flow(
            scopes=auth_config.scope,
            redirect_uri=auth_config.redirect_uri,
        )
        _auth_flows.store(flow["state"], flow)

        client_ip = _get_client_ip(request)
        audit.info("OAuth login initiated: ip=%s", client_ip)

        return RedirectResponse(url=flow["auth_uri"])

    @router.get("/auth/callback")
    def callback(request: Request):
        """Handle the OAuth2 authorization code callback from Entra ID."""
        client_ip = _get_client_ip(request)
        state = request.query_params.get("state", "")

        if not state:
            audit.warning("OAuth callback missing state: ip=%s", client_ip)
            return RedirectResponse(url="/auth/login")

        flow = _auth_flows.pop(state)
        if flow is None:
            audit.warning("OAuth callback invalid/expired state: ip=%s", client_ip)
            return RedirectResponse(url="/auth/login")

        app = auth_config.get_msal_app()
        result = app.acquire_token_by_auth_code_flow(
            flow, dict(request.query_params)
        )

        if "access_token" not in result:
            error = result.get("error_description", "Unknown error")
            audit.warning("OAuth token acquisition failed: ip=%s error=%s", client_ip, error)
            return RedirectResponse(url="/auth/login")

        # Fetch user profile from Microsoft Graph
        headers = {"Authorization": f"Bearer {result['access_token']}"}
        try:
            user_response = httpx.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers,
                timeout=10,
            )
            user_response.raise_for_status()
            user_info = user_response.json()
        except (httpx.HTTPError, Exception):
            audit.warning("Failed to fetch user profile: ip=%s", client_ip)
            return RedirectResponse(url="/auth/login")

        email = (
            user_info.get("mail")
            or user_info.get("userPrincipalName", "unknown")
        )
        display_name = user_info.get("displayName", "")

        # Create session
        token = _sessions.create(email=email, name=display_name)

        audit.info("User logged in: email=%s ip=%s", email, client_ip)

        response = RedirectResponse(url="/dashboard")
        response.set_cookie(
            "azsploit_session",
            token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=SESSION_MAX_AGE,
        )
        return response

    @router.get("/auth/logout")
    def logout(request: Request):
        """Log out the current user and destroy their session."""
        client_ip = _get_client_ip(request)
        token = request.cookies.get("azsploit_session")

        if token:
            session = _sessions.get(token)
            if session:
                audit.info("User logged out: email=%s ip=%s", session["email"], client_ip)
            _sessions.delete(token)

        response = RedirectResponse(url="/auth/login")
        response.delete_cookie("azsploit_session")
        return response

    @router.get("/auth/me")
    def me(request: Request):
        """Return the current user's identity (requires authentication)."""
        # This endpoint is NOT exempt from auth middleware,
        # so request.state.user_email is always set if we reach here
        email = getattr(request.state, "user_email", "anonymous")
        return {"email": email}

    return router
