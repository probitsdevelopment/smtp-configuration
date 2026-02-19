"""
Google OAuth 2.0 integration module.
Handles the OAuth flow for authenticating with Google and fetching user information.
Supports gmail.send scope for email operations plus profile/email scopes for user info.
"""
import requests
from urllib.parse import urlencode

from json_log import log_event, safe_error_detail
from config import (
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    BACKEND_BASE_URL,
)

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


def create_google_consent_url(state: str):
    """
    Generate the Google OAuth consent URL to redirect the user to.
    This URL requests permissions for:
    - gmail.send: Send emails via Gmail API
    - openid, profile, email: Get user profile information
    
    Args:
        state: Random state token for CSRF protection
        
    Returns:
        Full OAuth consent URL to redirect user to
    """
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": "https://www.googleapis.com/auth/gmail.send openid profile email",
        "redirect_uri": f"{BACKEND_BASE_URL}/auth/google/callback",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }

    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def exchange_google_code_for_token(code: str):
    """
    Exchange the authorization code for OAuth tokens.
    Called after user grants consent on Google's login page.
    
    Args:
        code: Authorization code from Google OAuth callback
        
    Returns:
        Dictionary containing access_token, refresh_token, expires_in, etc.
        
    Raises:
        Exception: If token exchange fails
    """
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{BACKEND_BASE_URL}/auth/google/callback",
    }

    response = requests.post(GOOGLE_TOKEN_URL, data=data)

    if response.status_code != 200:
        log_event(
            {
                "action": "oauth_token_error",
                "provider": "google",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    return response.json()


def refresh_google_token(refresh_token: str):
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
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    response = requests.post(GOOGLE_TOKEN_URL, data=data)

    if response.status_code != 200:
        log_event(
            {
                "action": "oauth_refresh_error",
                "provider": "google",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    return response.json()

def get_google_user_info(access_token: str):
    """
    Fetch authenticated user's profile information from Google.
    Uses the userinfo endpoint with the access token.
    This function is NEW - added to retrieve user name and email.
    
    Args:
        access_token: Valid Google OAuth access token
        
    Returns:
        Dictionary containing:
        - user_name: User's display name (from 'name' field)
        - user_email: User's email address (from 'email' field)
        
    Raises:
        Exception: If userinfo endpoint returns error
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    
    response = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers=headers
    )

    if response.status_code != 200:
        log_event(
            {
                "action": "get_google_user_info_error",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    data = response.json()
    return {
        "user_name": data.get("name"),
        "user_email": data.get("email"),
    }