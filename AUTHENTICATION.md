# Authentication Documentation

## Overview

This Email POC application implements OAuth 2.0 authentication to securely connect users' Gmail (Google) and Outlook (Microsoft) accounts. The system allows users to send emails through their own email providers without storing passwords, using secure OAuth tokens instead.

## Supported Providers

- **Google** (Gmail) - Uses Google OAuth 2.0
- **Microsoft** (Outlook) - Uses Microsoft Azure OAuth 2.0

## Architecture

### High-Level Flow

```
Frontend                    Backend                 OAuth Provider
    |                          |                           |
    |--Click Connect Button---->|                           |
    |                          |--Generate Auth URL------->|
    |<-Redirect to Auth Page---|                           |
    |    (User logs in & consents)                         |
    |                          |<-Redirect with Code-------|
    |<-Redirect to Callback----|                           |
    |                          |--Exchange Code for Token->|
    |<-Saved & Redirected------|<-Token Response-----------|
    |
    |--Send Email with Token-->|--Use Token to Send Email->|
    |                          |                           |
```

## Frontend Implementation

**File:** [frontend/src/pages/Email.js](frontend/src/pages/Email.js)

### User Interface Flow

1. **Connection Check** - On page load, fetches `/status` endpoint to check if user is already connected
2. **Connect Buttons** - Displays Google and Microsoft connection buttons if not connected
3. **Connection Flow**:
   - User clicks "Connect Gmail" or "Connect Outlook" button
   - Browser redirects to backend auth endpoint (`/auth/google` or `/auth/microsoft`)
   - Backend initiates OAuth consent flow
   - User logs in with their provider and grants permissions
   - After successful auth, browser redirects back to `/email?provider=<provider>`
   - Frontend detects provider in URL and sets state to connected

4. **Email Form** - Once connected, user can:
   - Enter recipient email address (`to`)
   - Enter email subject
   - Enter email message body
   - Click "Send Email" button

5. **Email Sending** - Frontend makes POST request to:
   - `/send/google` for Gmail
   - `/send/microsoft` for Outlook

### State Management

```javascript
const [provider, setProvider] = useState(null);           // Current connected provider
const [connected, setConnected] = useState(false);         // Connection status
const [lastLoginAt, setLastLoginAt] = useState(null);      // Last successful login timestamp
const [lastRefreshedAt, setLastRefreshedAt] = useState(null); // Last token refresh timestamp
```

## Backend Implementation

### Architecture

**Files:**
- [backend/main.py](backend/main.py) - Main FastAPI application with OAuth endpoints
- [backend/oauth/google.py](backend/oauth/google.py) - Google OAuth helper functions
- [backend/oauth/microsoft.py](backend/oauth/microsoft.py) - Microsoft OAuth helper functions
- [backend/storage.py](backend/storage.py) - PostgreSQL database operations
- [backend/config.py](backend/config.py) - Configuration and environment variables

### Key Components

#### 1. OAuth Flow Endpoints

**Google OAuth:**
- `GET /auth/google?org=<org_name>` - Initiates Google OAuth consent
  - Generates random state token
  - Saves state to database for validation
  - Redirects to Google OAuth endpoint with scopes: `gmail.send`

- `GET /auth/google/callback?code=<code>&state=<state>` - Handles Google OAuth callback
  - Validates state token (CSRF protection)
  - Exchanges authorization code for access/refresh tokens
  - Saves tokens to database
  - Redirects to frontend at `{FRONTEND_BASE_URL}/email?provider=google`

**Microsoft OAuth:**
- `GET /auth/microsoft?org=<org_name>` - Initiates Microsoft OAuth consent
  - Generates random state token
  - Saves state to database for validation
  - Redirects to Microsoft OAuth endpoint with scopes: `offline_access User.Read Mail.Send`

- `GET /auth/microsoft/callback?code=<code>&state=<state>` - Handles Microsoft OAuth callback
  - Validates state token (CSRF protection)
  - Exchanges authorization code for access/refresh tokens
  - Saves tokens to database
  - Redirects to frontend at `{FRONTEND_BASE_URL}/email?provider=microsoft`

#### 2. Email Sending Endpoints

**Google Email:**
- `POST /send/google` - Send email via Gmail
  - Payload: `{ to, subject, message }`
  - Header: `x-org-name` (optional, defaults to "default")
  - Retrieves valid access token (refreshes if expired)
  - Calls `send_gmail_message()` with token
  - Logs email send metrics

**Microsoft Email:**
- `POST /send/microsoft` - Send email via Outlook
  - Payload: `{ to, subject, message }`
  - Header: `x-org-name` (optional, defaults to "default")
  - Retrieves valid access token (refreshes if expired)
  - Calls `send_outlook_message()` with token
  - Logs email send metrics

#### 3. Status Endpoint

- `GET /status?org=<org_name>` - Check connection status
  - Returns list of connected providers
  - Includes `expires_at`, `updated_at`, `last_login_at`, `last_refresh_at`

#### 4. Logout Endpoint

- `POST /logout?org=<org_name>` - Clear all tokens for org
  - Deletes all token data from database
  - Effectively disconnects the user

### Token Management Flow

```
User initiates action requiring access token
        |
        v
_get_valid_access_token(provider, org_name)
        |
        +----> Retrieve tokens from DB
        |
        v
Is token expired or about to expire? (with 60s skew)
        |
        +----> NO: Return access_token
        |
        v
    YES: Has refresh_token?
        |
        +----> NO: Raise 401 "Token Expired"
        |
        v
    YES: Refresh token
        |
        +----> Call provider's token refresh endpoint
        +----> Get new access token
        +----> Save new tokens to DB
        +----> Return new access_token
```

**Token Expiry Skew:** 60 seconds
- Tokens are considered expired 60 seconds before actual expiration
- This prevents using tokens that might expire mid-request

#### 5. State Token Generation and Validation

**Generation (OAuth Initiation):**
```python
state = secrets.token_urlsafe(32)  # Cryptographically secure random token
save_oauth_state(org_name, provider, state)  # Save to DB with timestamp
```

**Validation (OAuth Callback):**
```
Receive state from provider
        |
        v
Lookup state in DB
        |
        v
Validate state matches exactly
        |
        v
Check state age < 600 seconds (10 minutes)
        |
        v
If valid: Clear state from DB and use org_name
If invalid: Reject callback (CSRF attack attempt)
```

### Token Storage Schema

**PostgreSQL Table: `oauth_connections`**

| Column | Type | Purpose |
|--------|------|---------|
| `org_name` | TEXT | Organization/user identifier (PRIMARY KEY) |
| `provider` | TEXT | "google" or "microsoft" (PRIMARY KEY) |
| `state` | TEXT | CSRF protection token during OAuth flow |
| `state_created_at` | BIGINT | Timestamp when state was generated |
| `access_token` | TEXT | Current access token for API calls |
| `refresh_token` | TEXT | Long-lived token to get new access tokens |
| `expires_at` | BIGINT | Unix timestamp when access token expires |
| `token_type` | TEXT | "Bearer" |
| `scope` | TEXT | Permissions granted by OAuth consent |
| `last_login_at` | BIGINT | Timestamp of last successful OAuth login |
| `last_refresh_at` | BIGINT | Timestamp of last token refresh |
| `updated_at` | BIGINT | Timestamp of last row update |

### Configuration

**File:** [backend/config.py](backend/config.py)

Required environment variables:
```
GOOGLE_CLIENT_ID         # Google OAuth app client ID
GOOGLE_CLIENT_SECRET     # Google OAuth app secret
MICROSOFT_CLIENT_ID      # Microsoft OAuth app client ID
MICROSOFT_CLIENT_SECRET  # Microsoft OAuth app secret
MICROSOFT_TENANT_ID      # Microsoft Azure tenant ID
BACKEND_BASE_URL         # Backend URL (for OAuth callbacks)
DATABASE_URL             # PostgreSQL connection string
```

Optional environment variables:
```
FRONTEND_BASE_URL        # Frontend URL (defaults to http://localhost:3000)
ORG_NAME                 # Default organization name (defaults to "default")
CORS_ORIGINS             # Comma-separated list of allowed CORS origins
```

## OAuth Scopes

### Google Scopes
- **Scope:** `https://www.googleapis.com/auth/gmail.send`
- **Permission:** Send emails only (no read/modify permissions)
- **Access Type:** Offline (can refresh without re-prompting)

### Microsoft Scopes
- **Scopes:** `offline_access User.Read Mail.Send`
- **Permissions:**
  - `offline_access` - Can refresh tokens without user interaction
  - `User.Read` - Read user profile information
  - `Mail.Send` - Send emails on behalf of user

## Security Considerations

### 1. CSRF Protection
- **State Token:** Cryptographically secure random token generated for each OAuth initiation
- **Validation:** State token must match exactly and be within 10-minute TTL
- **Cleanup:** State token is cleared from database after validation

### 2. Token Storage
- **Database:** Tokens stored in PostgreSQL (encrypted at rest with provider)
- **No Local Storage:** Tokens NOT stored in browser/cookies
- **Secure Transport:** Always use HTTPS in production

### 3. Token Refresh
- **Automatic:** Access tokens automatically refreshed before expiration
- **Smart Expiry:** Tokens considered expired 60 seconds before actual expiration
- **Refresh Token Storage:** Refresh tokens preserved across refreshes

### 4. Scope Limitation
- **Google:** Limited to `gmail.send` only (no read/archive/delete)
- **Microsoft:** Limited to sending mail and reading basic user info

### 5. Organization Isolation
- **Multi-tenancy:** Different organizations can connect separate accounts
- **Org Name Header:** `x-org-name` header used to isolate org data
- **Default Org:** "default" organization used if no org specified

### 6. Error Logging
- **Safe Errors:** All errors logged without exposing sensitive data
- **Token Security:** Access tokens not logged, only metadata
- **Error Details:** Safe error details extracted (no full stack traces or credentials)

## Refresh Token Flow

### When Does Refresh Happen?

Token refresh occurs automatically when:
1. User attempts to send an email
2. Access token is expired OR will expire within 60 seconds
3. Refresh token exists and is valid

### Refresh Process

```python
# Check if token expired or expiring soon
now = int(time.time())
expires_at = tokens.get("expires_at")

if expires_at and now + 60 >= expires_at:  # 60s skew
    refresh_token = tokens.get("refresh_token")
    
    # Call provider's refresh endpoint
    if provider == "google":
        refreshed = refresh_google_token(refresh_token)
    else:
        refreshed = refresh_microsoft_token(refresh_token)
    
    # Save new tokens
    normalized = _normalize_token_response(refreshed, existing_refresh_token=refresh_token)
    save_tokens(org_name, provider, normalized, last_refresh_at=int(time.time()))
```

### Important Notes
- **Refresh Token Preservation:** If provider doesn't return new refresh token, old one is reused
- **Single Metadata:** Only one `last_refresh_at` timestamp per provider per org
- **Token Expiry:** New `expires_at` is calculated as current time + `expires_in`

## Multi-Organization Support

The system supports multiple organizations (or users) connecting different accounts:

```
Organization 1: Google account + Microsoft account
Organization 2: Different Google account
Default Org: Single account setup
```

**Usage:**
- Set `x-org-name` header in email sending requests
- Pass `org` query parameter to OAuth initiation endpoints
- Tokens are isolated per organization per provider

## Logging

All authentication events are logged using [backend/json_log.py](backend/json_log.py):

**OAuth Events:**
- `oauth_consent_generated` - OAuth flow initiated
- `oauth_callback_received` - Callback from OAuth provider
- `oauth_error` - Error during OAuth flow
- `oauth_state_invalid` - State token validation failed
- `oauth_token_error` - Token exchange failed

**Token Events:**
- `token_refresh_start` - Token refresh initiated
- `token_refresh_failed` - Token refresh failed
- `token_expired_no_refresh` - Token expired but no refresh token available
- `token_missing` - No tokens found for org/provider

**Email Events:**
- `email_send_request` - Email send initiated
- `email_send_success` - Email sent successfully (includes latency)
- `email_send_failed` - Email send failed

## Testing the Flow

### 1. Connect Google Account
```bash
curl http://localhost:8000/auth/google
# Browser redirects to Google login
# After consent, redirects to http://localhost:3000/email?provider=google
```

### 2. Send Email via Google
```bash
curl -X POST http://localhost:8000/send/google \
  -H "Content-Type: application/json" \
  -d '{
    "to": "recipient@example.com",
    "subject": "Test Email",
    "message": "This is a test"
  }'
```

### 3. Check Connection Status
```bash
curl http://localhost:8000/status
```

### 4. Logout
```bash
curl -X POST http://localhost:8000/logout
```

## Troubleshooting

### Token Expired Errors
- **Cause:** Token refresh token is missing or invalid
- **Solution:** Reconnect the account (delete and re-authenticate)
- **Check:** Verify `refresh_token` exists in database

### State Validation Failed
- **Cause:** State token doesn't match or is older than 10 minutes
- **Solution:** Restart the connection flow
- **Check:** Ensure backend and database are in sync

### Missing Scopes
- **Cause:** User didn't grant all required permissions during consent
- **Solution:** Prompt user to re-authenticate with correct scopes
- **Result:** Email send will fail if scopes insufficient

### CORS Errors
- **Cause:** Frontend and backend domains don't match
- **Solution:** Update `CORS_ORIGINS` environment variable
- **Check:** See `config.py` for CORS configuration
