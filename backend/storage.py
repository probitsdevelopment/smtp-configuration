"""
Storage module for OAuth token and user information management.
Handles database operations for storing and retrieving OAuth connections,
tokens, and authenticated user details.
"""
import time
from typing import Optional, Dict, Any, List

import psycopg2
from psycopg2.extras import RealDictCursor

from config import DATABASE_URL
from json_log import log_event


def _get_connection():
    """
    Establish a connection to the PostgreSQL database.
    Returns: A psycopg2 connection object
    """
    return psycopg2.connect(DATABASE_URL)


def init_db() -> None:
    """
    Initialize the database schema by creating the oauth_connections table
    and adding required columns if they don't exist.
    This ensures the database structure is ready for OAuth operations.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_connections (
                    org_name TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    state TEXT,
                    state_created_at BIGINT,
                    access_token TEXT,
                    refresh_token TEXT,
                    expires_at BIGINT,
                    token_type TEXT,
                    scope TEXT,
                    last_login_at BIGINT,
                    last_refresh_at BIGINT,
                    updated_at BIGINT,
                    PRIMARY KEY (org_name, provider)
                )
                """
            )
            cur.execute(
                """
                ALTER TABLE oauth_connections
                ADD COLUMN IF NOT EXISTS last_login_at BIGINT
                """
            )
            cur.execute(
                """
                ALTER TABLE oauth_connections
                ADD COLUMN IF NOT EXISTS last_refresh_at BIGINT
                """
            )
            cur.execute(
                """
                ALTER TABLE oauth_connections
                ADD COLUMN IF NOT EXISTS user_name TEXT
                """
            )
            cur.execute(
                """
                ALTER TABLE oauth_connections
                ADD COLUMN IF NOT EXISTS user_email TEXT
                """
            )
        conn.commit()


def save_oauth_state(org_name: str, provider: str, state: str) -> None:
    """
    Save OAuth state token to database for CSRF protection.
    The state token is used to verify that the OAuth response matches
    the original request. It's stored with a timestamp for validation.
    
    Args:
        org_name: Organization identifier
        provider: OAuth provider (e.g., 'google', 'microsoft')
        state: Random state token generated for this OAuth flow
    """
    now = int(time.time())
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO oauth_connections (
                    org_name,
                    provider,
                    state,
                    state_created_at
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (org_name, provider) DO UPDATE SET
                    state=EXCLUDED.state,
                    state_created_at=EXCLUDED.state_created_at
                """,
                (org_name, provider, state, now),
            )
        conn.commit()
    log_event(
        {
            "action": "save_oauth_state",
            "org_name": org_name,
            "provider": provider,
            "state": state,
            "state_created_at": now,
        }
    )


def consume_oauth_state(provider: str, state: str, max_age_seconds: int) -> Optional[str]:
    """
    Validate and consume the OAuth state token (one-time use).
    Verifies that:
    1. The state exists in the database (CSRF check)
    2. The state hasn't expired (time validation)
    3. Clears the state after consumption to prevent replay attacks
    
    Args:
        provider: OAuth provider 
        state: State token from the OAuth callback
        max_age_seconds: Maximum age of state token in seconds
        
    Returns:
        Organization name if state is valid and not expired, None otherwise
    """
    now = int(time.time())
    with _get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT org_name, state, state_created_at
                FROM oauth_connections
                WHERE provider = %s AND state = %s
                """,
                (provider, state),
            )
            row = cur.fetchone()

            if not row:
                return None

            if row["state"] != state:
                return None

            if not row["state_created_at"]:
                return None

            if now - int(row["state_created_at"]) > max_age_seconds:
                return None

            cur.execute(
                """
                UPDATE oauth_connections
                SET state = NULL, state_created_at = NULL
                WHERE org_name = %s AND provider = %s
                """,
                (row["org_name"], provider),
            )
        conn.commit()
        log_event(
            {
                "action": "consume_oauth_state",
                "org_name": row["org_name"],
                "provider": provider,
                "state": state,
            }
        )
        return row["org_name"]


def save_tokens(
    org_name: str,
    provider: str,
    token_data: Dict[str, Any],
    last_login_at: Optional[int] = None,
    last_refresh_at: Optional[int] = None,
    user_name: Optional[str] = None,
    user_email: Optional[str] = None,
) -> None:
    """
    Save or update OAuth tokens and user information.
    Stores access tokens, refresh tokens, expiration details, and user profile data.
    Uses UPSERT logic to update existing records for the same org+provider combination.
    
    Args:
        org_name: Organization identifier
        provider: OAuth provider (e.g., 'google', 'microsoft')
        token_data: Dictionary containing token details (access_token, refresh_token, expires_at, etc.)
        last_login_at: Unix timestamp of last successful login
        last_refresh_at: Unix timestamp of last token refresh
        user_name: Authenticated user's full name  (NEW)
        user_email: Authenticated user's email address (NEW)
    """
    now = int(time.time())
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO oauth_connections (
                    org_name,
                    provider,
                    access_token,
                    refresh_token,
                    expires_at,
                    token_type,
                    scope,
                    last_login_at,
                    last_refresh_at,
                    user_name,
                    user_email,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (org_name, provider) DO UPDATE SET
                    access_token=EXCLUDED.access_token,
                    refresh_token=EXCLUDED.refresh_token,
                    expires_at=EXCLUDED.expires_at,
                    token_type=EXCLUDED.token_type,
                    scope=EXCLUDED.scope,
                    last_login_at=COALESCE(EXCLUDED.last_login_at, oauth_connections.last_login_at),
                    last_refresh_at=COALESCE(EXCLUDED.last_refresh_at, oauth_connections.last_refresh_at),
                    user_name=COALESCE(EXCLUDED.user_name, oauth_connections.user_name),
                    user_email=COALESCE(EXCLUDED.user_email, oauth_connections.user_email),
                    updated_at=EXCLUDED.updated_at
                """,
                (
                    org_name,
                    provider,
                    token_data.get("access_token"),
                    token_data.get("refresh_token"),
                    token_data.get("expires_at"),
                    token_data.get("token_type"),
                    token_data.get("scope"),
                    last_login_at,
                    last_refresh_at,
                    user_name,
                    user_email,
                    now,
                ),
            )
        conn.commit()
    log_event(
        {
            "action": "save_tokens",
            "org_name": org_name,
            "provider": provider,
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_at": token_data.get("expires_at"),
            "token_type": token_data.get("token_type"),
            "scope": token_data.get("scope"),
            "last_login_at": last_login_at,
            "last_refresh_at": last_refresh_at,
            "updated_at": now,
        }
    )


def get_tokens(org_name: str, provider: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve stored OAuth tokens for a given organization and provider.
    Used to get access/refresh tokens for making authenticated API calls.
    
    Args:
        org_name: Organization identifier
        provider: OAuth provider
        
    Returns:
        Dictionary with token details if found, None otherwise
    """
    with _get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT access_token, refresh_token, expires_at, token_type, scope
                FROM oauth_connections
                WHERE org_name = %s AND provider = %s
                """,
                (org_name, provider),
            )
            row = cur.fetchone()

            if not row:
                return None

            return {
                "access_token": row["access_token"],
                "refresh_token": row["refresh_token"],
                "expires_at": row["expires_at"],
                "token_type": row["token_type"],
                "scope": row["scope"],
            }


def clear_tokens() -> None:
    """
    Clear all OAuth tokens from the database.
    Used for complete logout or testing purposes.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM oauth_connections")
        conn.commit()
    log_event({"action": "clear_tokens"})


def clear_tokens_for_org(org_name: str, provider: Optional[str] = None) -> None:
    """
    Clear OAuth tokens for a specific organization.
    Can clear tokens for all providers or a specific provider.
    
    Args:
        org_name: Organization identifier
        provider: Optional - if provided, only clears tokens for this provider;
                  if None, clears all providers for the organization
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            if provider:
                cur.execute(
                    """
                    DELETE FROM oauth_connections
                    WHERE org_name = %s AND provider = %s
                    """,
                    (org_name, provider),
                )
            else:
                cur.execute(
                    """
                    DELETE FROM oauth_connections
                    WHERE org_name = %s
                    """,
                    (org_name,),
                )
        conn.commit()
    log_event(
        {
            "action": "clear_tokens_for_org",
            "org_name": org_name,
            "provider": provider,
        }
    )


def get_connected_providers(org_name: str) -> List[Dict[str, Any]]:
    """
    Get list of all connected OAuth providers for an organization.
    Returns provider status including user profile info (name, email).
    
    Args:
        org_name: Organization identifier
        
    Returns:
        List of dictionaries containing provider details and user information
    """
    with _get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT provider, expires_at, updated_at, last_login_at, last_refresh_at, user_name, user_email
                FROM oauth_connections
                WHERE org_name = %s AND access_token IS NOT NULL
                ORDER BY updated_at DESC NULLS LAST
                """,
                (org_name,),
            )
            rows = cur.fetchall()

            return [
                {
                    "provider": row["provider"],
                    "expires_at": row["expires_at"],
                    "updated_at": row["updated_at"],
                    "last_login_at": row["last_login_at"],
                    "last_refresh_at": row["last_refresh_at"],
                    "user_name": row["user_name"],
                    "user_email": row["user_email"],
                }
                for row in rows
            ]


def get_user_info(org_name: str, provider: str) -> Optional[Dict[str, str]]:
    """
    Retrieve authenticated user's profile information (name and email).
    
    Args:
        org_name: Organization identifier
        provider: OAuth provider
        
    Returns:
        Dictionary with user_name and user_email if found, None otherwise
    """
    with _get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT user_name, user_email
                FROM oauth_connections
                WHERE org_name = %s AND provider = %s
                """,
                (org_name, provider),
            )
            row = cur.fetchone()

            if not row:
                return None

            return {
                "user_name": row["user_name"],
                "user_email": row["user_email"],
            }
