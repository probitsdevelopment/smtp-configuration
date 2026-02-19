"""
Main FastAPI application for Email POC.
Implements OAuth 2.0 authentication for Google and Microsoft,
with user profile fetching and email sending capabilities.

Key Features:
- OAuth consent flow with CSRF protection
- Token refresh and expiration handling
- User profile (name, email) extraction
- Email sending via Gmail and Outlook
- Multi-tenant support via organization names
"""
import secrets
import time
from typing import Optional

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field

from oauth.google import (
    create_google_consent_url,
    exchange_google_code_for_token,
    refresh_google_token,
    get_google_user_info,
)

from oauth.microsoft import (
    create_microsoft_consent_url,
    exchange_microsoft_code_for_token,
    refresh_microsoft_token,
    get_microsoft_user_info,
)

from mail.google_send import send_gmail_message
from mail.microsoft_send import send_outlook_message
from storage import (
    init_db,
    save_oauth_state,
    consume_oauth_state,
    save_tokens,
    get_tokens,
    clear_tokens,
    clear_tokens_for_org,
    get_connected_providers,
    get_user_info,
)
from json_log import log_event, safe_error_detail
from config import FRONTEND_BASE_URL, CORS_ORIGINS, DEFAULT_ORG_NAME


# Configuration constants
FRONTEND_EMAIL_URL = f"{FRONTEND_BASE_URL}/email"
STATE_TTL_SECONDS = 600  # OAuth state tokens expire after 10 minutes
TOKEN_EXPIRY_SKEW_SECONDS = 60  # Refresh tokens 60 seconds before actual expiry

app = FastAPI()


# Request body validation schema for email sending
class EmailPayload(BaseModel):
    """Validated schema for email sending requests."""
    to: str = Field(..., min_length=3, max_length=320)  # Valid email address
    subject: str = Field(..., min_length=1, max_length=200)  # Email subject
    message: str = Field(..., min_length=1, max_length=5000)  # Email body

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    log_event(
        {
            "action": "app_startup",
            "frontend_base_url": FRONTEND_BASE_URL,
            "cors_origins": CORS_ORIGINS,
        }
    )


@app.on_event("shutdown")
def shutdown() -> None:
    log_event({"action": "app_shutdown"})


@app.get("/")
def health():
    return {"status": "backend running"}


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc: RequestValidationError):
    log_event(
        {
            "action": "validation_error",
            "path": request.url.path,
            "errors": exc.errors(),
        }
    )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    log_event(
        {
            "action": "http_error",
            "path": request.url.path,
            "status_code": exc.status_code,
            "detail": safe_error_detail(exc.detail),
        }
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


def _normalize_token_response(token_response: dict, existing_refresh_token: Optional[str] = None) -> dict:
    """
    Normalize OAuth token response into consistent format for storage.
    Converts relative expiry (expires_in) to absolute timestamp (expires_at).
    Falls back to existing refresh token if provider doesn't return a new one.
    
    Args:
        token_response: Raw response from OAuth provider's token endpoint
        existing_refresh_token: Optional existing refresh token to preserve
        
    Returns:
        Normalized token dictionary ready for database storage
    """
    access_token = token_response.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Missing access token")

    refresh_token = token_response.get("refresh_token") or existing_refresh_token
    expires_in = token_response.get("expires_in")
    expires_at = int(time.time()) + int(expires_in) if expires_in else None

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "token_type": token_response.get("token_type"),
        "scope": token_response.get("scope"),
    }


def _resolve_org_name(org_name: Optional[str]) -> str:
    """
    Determine the organization name.
    Uses provided org_name or falls back to DEFAULT_ORG_NAME if not provided.
    """
    return (org_name or DEFAULT_ORG_NAME).strip() or DEFAULT_ORG_NAME


def _get_valid_access_token(provider: str, org_name: str) -> str:
    """
    Get a valid access token, refreshing if necessary.
    
    Flow:
    1. Retrieve stored tokens for the provider
    2. Check if token is expired or about to expire (with 60-second skew)
    3. If expired, use refresh token to get a new access token
    4. Update stored token expiry information
    5. Return valid access token
    
    Args:
        provider: OAuth provider ('google' or 'microsoft')
        org_name: Organization identifier
        
    Returns:
        Valid access token ready for API calls
        
    Raises:
        HTTPException: If tokens missing, expired, or refresh fails
    """
    tokens = get_tokens(org_name, provider)
    if not tokens:
        log_event(
            {
                "action": "token_missing",
                "provider": provider,
                "org_name": org_name,
            }
        )
        raise HTTPException(status_code=401, detail=f"{provider.capitalize()} not connected")

    now = int(time.time())
    expires_at = tokens.get("expires_at")
    if expires_at and now + TOKEN_EXPIRY_SKEW_SECONDS >= int(expires_at):
        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            log_event(
                {
                    "action": "token_expired_no_refresh",
                    "provider": provider,
                    "org_name": org_name,
                }
            )
            raise HTTPException(status_code=401, detail=f"{provider.capitalize()} token expired")

        log_event(
            {
                "action": "token_refresh_start",
                "provider": provider,
                "org_name": org_name,
            }
        )
        try:
            if provider == "google":
                refreshed = refresh_google_token(refresh_token)
            elif provider == "microsoft":
                refreshed = refresh_microsoft_token(refresh_token)
            else:
                raise HTTPException(status_code=400, detail="Unknown provider")
        except Exception as exc:
            log_event(
                {
                    "action": "token_refresh_failed",
                    "provider": provider,
                    "org_name": org_name,
                    "error": safe_error_detail(exc),
                }
            )
            raise

        normalized = _normalize_token_response(refreshed, existing_refresh_token=refresh_token)
        save_tokens(org_name, provider, normalized, last_refresh_at=int(time.time()))
        tokens = normalized

    return tokens.get("access_token")


# ======================================================
# GOOGLE OAUTH + GMAIL SEND 
# ======================================================

@app.get("/auth/google")
def google_consent(org: Optional[str] = None):
    """
    Step 1: Initiate Google OAuth consent flow.
    
    Process:
    1. Generate random state token for CSRF protection
    2. Save state token to database with timestamp
    3. Redirect user to Google's OAuth consent page
    
    Args:
        org: Optional organization name from query parameter
        
    Returns:
        Redirect to Google OAuth consent URL
    """
    org_name = _resolve_org_name(org)
    state = secrets.token_urlsafe(32)
    save_oauth_state(org_name, "google", state)
    log_event(
        {
            "action": "oauth_consent_generated",
            "provider": "google",
            "org_name": org_name,
        }
    )
    return RedirectResponse(create_google_consent_url(state))


@app.get("/auth/google/callback")
def google_callback(code: str = None, error: str = None, state: str = None):
    """
    Step 2: Handle Google OAuth callback.
    
    Process:
    1. Validate state token (CSRF protection)
    2. Exchange authorization code for tokens
    3. Normalize token response
    4. FETCH USER INFO (NEW) - Get name and email from Google
    5. Save tokens and user info to database
    6. Redirect to frontend email page
    
    Args:
        code: Authorization code from Google
        error: Error message if user denied permission
        state: State token for CSRF validation
        
    Returns:
        Redirect to frontend with provider info
    """
    log_event(
        {
            "action": "oauth_callback_received",
            "provider": "google",
            "has_code": bool(code),
            "has_state": bool(state),
            "has_error": bool(error),
        }
    )
    if error:
        log_event(
            {
                "action": "oauth_error",
                "provider": "google",
                "error": safe_error_detail(error),
            }
        )
        raise HTTPException(status_code=400, detail=error)

    if not code or not state:
        log_event(
            {
                "action": "oauth_validation_error",
                "provider": "google",
                "missing_code": not bool(code),
                "missing_state": not bool(state),
            }
        )
        raise HTTPException(status_code=400, detail="Missing authorization code")

    org_name = consume_oauth_state("google", state, STATE_TTL_SECONDS)
    if not org_name:
        log_event(
            {
                "action": "oauth_state_invalid",
                "provider": "google",
            }
        )
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    tokens = exchange_google_code_for_token(code)
    normalized = _normalize_token_response(tokens)
    
    # Fetch user info
    try:
        user_info = get_google_user_info(normalized["access_token"])
        save_tokens(
            org_name, 
            "google", 
            normalized, 
            last_login_at=int(time.time()),
            user_name=user_info.get("user_name"),
            user_email=user_info.get("user_email"),
        )
    except Exception as exc:
        log_event(
            {
                "action": "google_user_info_fetch_failed",
                "org_name": org_name,
                "error": safe_error_detail(exc),
            }
        )
        # Still save tokens even if user info fetch fails
        save_tokens(org_name, "google", normalized, last_login_at=int(time.time()))

    return RedirectResponse(f"{FRONTEND_EMAIL_URL}?provider=google")


# ======================================================
# MICROSOFT OAUTH + SEND 
# ======================================================

@app.get("/auth/microsoft")
def microsoft_consent(org: Optional[str] = None):
    org_name = _resolve_org_name(org)
    state = secrets.token_urlsafe(32)
    save_oauth_state(org_name, "microsoft", state)
    log_event(
        {
            "action": "oauth_consent_generated",
            "provider": "microsoft",
            "org_name": org_name,
        }
    )
    return RedirectResponse(create_microsoft_consent_url(state))


@app.get("/auth/microsoft/callback")
def microsoft_callback(code: str = None, error: str = None, state: str = None):
    log_event(
        {
            "action": "oauth_callback_received",
            "provider": "microsoft",
            "has_code": bool(code),
            "has_state": bool(state),
            "has_error": bool(error),
        }
    )
    if error:
        log_event(
            {
                "action": "oauth_error",
                "provider": "microsoft",
                "error": safe_error_detail(error),
            }
        )
        raise HTTPException(status_code=400, detail=error)

    if not code or not state:
        log_event(
            {
                "action": "oauth_validation_error",
                "provider": "microsoft",
                "missing_code": not bool(code),
                "missing_state": not bool(state),
            }
        )
        raise HTTPException(status_code=400, detail="Missing authorization code")

    org_name = consume_oauth_state("microsoft", state, STATE_TTL_SECONDS)
    if not org_name:
        log_event(
            {
                "action": "oauth_state_invalid",
                "provider": "microsoft",
            }
        )
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    tokens = exchange_microsoft_code_for_token(code)
    normalized = _normalize_token_response(tokens)
    
    # Fetch user info
    try:
        user_info = get_microsoft_user_info(normalized["access_token"])
        save_tokens(
            org_name, 
            "microsoft", 
            normalized, 
            last_login_at=int(time.time()),
            user_name=user_info.get("user_name"),
            user_email=user_info.get("user_email"),
        )
    except Exception as exc:
        log_event(
            {
                "action": "microsoft_user_info_fetch_failed",
                "org_name": org_name,
                "error": safe_error_detail(exc),
            }
        )
        # Still save tokens even if user info fetch fails
        save_tokens(org_name, "microsoft", normalized, last_login_at=int(time.time()))

    return RedirectResponse(f"{FRONTEND_EMAIL_URL}?provider=microsoft")


@app.post("/send/microsoft")
def send_microsoft_email(payload: EmailPayload, x_org_name: Optional[str] = Header(default=None)):
    org_name = _resolve_org_name(x_org_name)
    log_event(
        {
            "action": "email_send_request",
            "provider": "microsoft",
            "org_name": org_name,
            "to": payload.to,
            "subject_len": len(payload.subject),
            "message_len": len(payload.message),
        }
    )
    access_token = _get_valid_access_token("microsoft", org_name)

    try:
        start = time.monotonic()
        send_outlook_message(
            access_token=access_token,
            to=payload.to,
            subject=payload.subject,
            body=payload.message,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        log_event(
            {
                "action": "email_send_success",
                "provider": "microsoft",
                "org_name": org_name,
                "latency_ms": elapsed_ms,
            }
        )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000) if "start" in locals() else None
        log_event(
            {
                "action": "email_send_failed",
                "provider": "microsoft",
                "org_name": org_name,
                "latency_ms": elapsed_ms,
                "error": safe_error_detail(exc),
            }
        )
        raise HTTPException(status_code=502, detail="Failed to send Outlook message") from exc

    return {"status": "sent"}


@app.get("/status")
def auth_status(x_org_name: Optional[str] = Header(default=None)):
    """
    Check auth status and get connected providers with user info.
    Returns list of connected providers and their details including
    user name and email (NEW).
    """
    org_name = _resolve_org_name(x_org_name)
    providers = get_connected_providers(org_name)
    return {
        "connected": len(providers) > 0,
        "providers": providers,
    }


@app.get("/user-info")
def get_user_info_endpoint(provider: str, x_org_name: Optional[str] = Header(default=None)):
    """
    Get authenticated user's name and email for a specific provider.
    This NEW endpoint retrieves the user profile information that was
    fetched during OAuth callback and stored in the database.
    
    Args:
        provider: OAuth provider ('google' or 'microsoft')
        x_org_name: Optional organization header
        
    Returns:
        JSON with user_name and user_email fields
    """
    org_name = _resolve_org_name(x_org_name)
    user_info = get_user_info(org_name, provider)
    if not user_info:
        raise HTTPException(status_code=404, detail="User info not found")
    return user_info


# ======================================================
# LOGOUT
# ======================================================

@app.post("/logout")
def logout(provider: Optional[str] = None, x_org_name: Optional[str] = Header(default=None)):
    """
    Logout user by clearing OAuth tokens.
    
    Args:
        provider: Optional - if provided, clears only this provider's tokens;
                  if None, clears all providers
        x_org_name: Optional organization header
        
    Returns:
        JSON confirming logout status
    """
    org_name = _resolve_org_name(x_org_name)
    if provider:
        clear_tokens_for_org(org_name, provider)
    else:
        clear_tokens_for_org(org_name)
    return {"status": "logged out"}
