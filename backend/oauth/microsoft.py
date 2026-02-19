"""
Microsoft Azure OAuth 2.0 integration module.
Handles OAuth flow for authenticating with Microsoft accounts (Outlook/Office 365).
Supports Mail.Send for email operations and User.Read for user profile data.
"""
import requests
from urllib.parse import urlencode

from json_log import log_event, safe_error_detail
from config import (
    MICROSOFT_CLIENT_ID,
    MICROSOFT_CLIENT_SECRET,
    MICROSOFT_TENANT_ID,
    BACKEND_BASE_URL,
)

# Microsoft OAuth endpoints (tenant-specific)
AUTH_URL = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token"


def create_microsoft_consent_url(state: str):
    """
    Generate the Microsoft OAuth consent URL to redirect the user to.
    This URL requests permissions for:
    - offline_access: Get refresh tokens
    - User.Read: Read user profile
    - Mail.Send: Send emails via Microsoft Graph
    
    Args:
        state: Random state token for CSRF protection
        
    Returns:
        Full OAuth consent URL to redirect user to
    """
    params = {
        "client_id": MICROSOFT_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": f"{BACKEND_BASE_URL}/auth/microsoft/callback",
        "response_mode": "query",
        "scope": "offline_access User.Read Mail.Send",
        "prompt": "consent",
        "state": state,
    }

    return f"{AUTH_URL}?{urlencode(params)}"


def exchange_microsoft_code_for_token(code: str):
    """
    Exchange the authorization code for OAuth tokens.
    Called after user grants consent on Microsoft login page.
    
    Args:
        code: Authorization code from Microsoft OAuth callback
        
    Returns:
        Dictionary containing access_token, refresh_token, expires_in, etc.
        
    Raises:
        Exception: If token exchange fails
    """
    data = {
        "client_id": MICROSOFT_CLIENT_ID,
        "client_secret": MICROSOFT_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{BACKEND_BASE_URL}/auth/microsoft/callback",
    }

    response = requests.post(TOKEN_URL, data=data)

    if response.status_code != 200:
        log_event(
            {
                "action": "oauth_token_error",
                "provider": "microsoft",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    return response.json()


def refresh_microsoft_token(refresh_token: str):
    """
    Refresh the access token using the refresh token.
    Access tokens expire, so we use refresh tokens to get new ones
    without requiring user to login again.
    
    Args:
        refresh_token: Long-lived refresh token from initial OAuth exchange
        
    Returns:
        Dictionary with new access_token and updated expiration info
        
    Raises:
        Exception: If token refresh fails
    """
    data = {
        "client_id": MICROSOFT_CLIENT_ID,
        "client_secret": MICROSOFT_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "offline_access User.Read Mail.Send",
        "redirect_uri": f"{BACKEND_BASE_URL}/auth/microsoft/callback",
    }

    response = requests.post(TOKEN_URL, data=data)

    if response.status_code != 200:
        log_event(
            {
                "action": "oauth_refresh_error",
                "provider": "microsoft",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    return response.json()

def get_microsoft_user_info(access_token: str):
    """
    Fetch authenticated user's profile information from Microsoft Graph.
    Uses the /me endpoint which requires User.Read scope.
    This function is NEW - added to retrieve user name and email.
    
    Args:
        access_token: Valid Microsoft OAuth access token
        
    Returns:
        Dictionary containing:
        - user_name: User's display name (from 'displayName' field)
        - user_email: User's email address (from 'userPrincipalName' field)
        
    Raises:
        Exception: If Microsoft Graph /me endpoint returns error
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    
    response = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers=headers
    )

    if response.status_code != 200:
        log_event(
            {
                "action": "get_microsoft_user_info_error",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    data = response.json()
    return {
        "user_name": data.get("displayName"),
        "user_email": data.get("userPrincipalName"),
    }