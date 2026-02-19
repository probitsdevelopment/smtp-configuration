# Email POC: Implementation Guide for Twenty CRM-Style OAuth Flow

**Purpose:** Transform the Email POC from a simple OAuth implementation into an enterprise-grade, dual-flow authentication system like Twenty CRM
**Complexity:** High
**Estimated Timeline:** 2-3 weeks for full implementation

---

## Table of Contents

1. [Current State Analysis](#current-state-analysis)
2. [Target Architecture](#target-architecture)
3. [Implementation Roadmap](#implementation-roadmap)
4. [Database Schema Modifications](#database-schema-modifications)
5. [Backend Implementation](#backend-implementation)
6. [Frontend Implementation](#frontend-implementation)
7. [Security Enhancements](#security-enhancements)
8. [Testing & Deployment](#testing--deployment)

---

## Current State Analysis

### Email POC Current Architecture

```
CURRENT:
┌─────────────────────────────────────┐
│   Single OAuth Flow                 │
│                                     │
│   Google/Microsoft OAuth            │
│   ├─ Scope: gmail.send, Mail.Send   │
│   ├─ Purpose: Send emails           │
│   ├─ Storage: oauth_connections     │
│   │   └─ (org_name, provider)       │
│   │                                 │
│   └─ Usage: Direct API calls        │
│       ├─ POST /send/google          │
│       └─ POST /send/microsoft       │
│                                     │
│   No frontend token management      │
│   No background jobs                │
└─────────────────────────────────────┘
```

### Email POC Current Files

**Backend (FastAPI, Python):**
- `backend/main.py` - Main API
- `backend/oauth/google.py` - Google OAuth helpers
- `backend/oauth/microsoft.py` - Microsoft OAuth helpers
- `backend/storage.py` - PostgreSQL operations
- `backend/config.py` - Configuration

**Frontend (React, JavaScript):**
- `frontend/src/pages/Email.js` - Main email page
- Simple state management (useState)

**Database:**
```sql
CREATE TABLE oauth_connections (
  org_name TEXT,
  provider TEXT,
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
);
```

---

## Target Architecture

### What We're Building

```
TARGET (Like Twenty CRM):
┌────────────────────────────────────────────────┐
│   Flow 1: Login OAuth                          │
│   ├─ Scopes: email, profile (MINIMAL)          │
│   ├─ Purpose: Authenticate user into app       │
│   ├─ Result: JWT tokens (LoginToken)           │
│   └─ Storage: users table (+ JWT in memory)    │
│                                                │
├────────────────────────────────────────────────┤
│   Flow 2: APIs OAuth                           │
│   ├─ Scopes: gmail.send, calendar (BROAD)      │
│   ├─ Purpose: Sync emails/calendar             │
│   ├─ Result: Store in connected_accounts      │
│   ├─ Storage: connected_accounts table         │
│   │                                            │
│   └─ Usage: Background jobs                    │
│       ├─ FetchEmailsJob                        │
│       ├─ FetchCalendarJob                      │
│       └─ DeleteSyncedDataJob (on disconnect)  │
│                                                │
│   Features:                                    │
│   ├─ Automatic token refresh                  │
│   ├─ Message queuing (BullMQ/RQ)              │
│   ├─ Real-time sync status                    │
│   └─ User-level OAuth isolation               │
└────────────────────────────────────────────────┘
```

---

## Implementation Roadmap

### Phase 1: Setup & Infrastructure (Week 1)

#### 1.1 Install Dependencies

**Python (Backend):**
```bash
# JWT signing
pip install PyJWT

# Email/Calendar APIs
pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client
pip install microsoft-graph-core azure-identity msgraph-sdk

# Job queuing (choose one)
pip install celery redis  # Celery + Redis
# OR
pip install rq redis     # RQ + Redis

# Environment management
pip install python-dotenv

# User session management
pip install flask-session
# OR (for FastAPI)
pip install fastapi-sessions

# Type hints
pip install pydantic
```

**JavaScript (Frontend):**
```bash
npm install axios jwt-decode recoil
# Optional: state management upgrades
npm install zustand
```

#### 1.2 Database Migrations

**Step 1:** Create new tables

```sql
-- Users table (for authentication)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),  -- NULL if SSO-only
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  auth_provider VARCHAR(50) NOT NULL,  -- 'password', 'google', 'microsoft'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_email_verified BOOLEAN DEFAULT FALSE,
  email_verified_at TIMESTAMP
);

-- Connected accounts (for API access like email sending)
CREATE TABLE connected_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,  -- 'google', 'microsoft'
  email VARCHAR(255) NOT NULL,
  access_token TEXT NOT NULL,  -- encrypted
  refresh_token TEXT,  -- encrypted
  token_expires_at TIMESTAMP,
  scope TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_refresh_at TIMESTAMP,
  UNIQUE(user_id, provider)
);

-- Email sync status
CREATE TABLE email_sync_status (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connected_account_id UUID NOT NULL REFERENCES connected_accounts(id) ON DELETE CASCADE,
  sync_status VARCHAR(50) DEFAULT 'PENDING',  -- 'PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'PAUSED'
  sync_stage VARCHAR(50),  -- 'INITIAL', 'INCREMENTAL'
  last_sync_at TIMESTAMP,
  next_sync_at TIMESTAMP,
  error_message TEXT,
  synced_messages_count INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Synced messages (cache from Gmail/Outlook)
CREATE TABLE synced_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connected_account_id UUID NOT NULL REFERENCES connected_accounts(id) ON DELETE CASCADE,
  external_message_id VARCHAR(500) NOT NULL,  -- Gmail: msg_id, Outlook: message_id
  subject TEXT,
  body TEXT,
  from_email VARCHAR(255),
  to_email VARCHAR(255),
  cc TEXT,
  bcc TEXT,
  received_at TIMESTAMP,
  is_read BOOLEAN DEFAULT FALSE,
  labels TEXT,  -- JSON array
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(connected_account_id, external_message_id)
);

-- Calendar events (cache from Google Calendar / Outlook Calendar)
CREATE TABLE calendar_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connected_account_id UUID NOT NULL REFERENCES connected_accounts(id) ON DELETE CASCADE,
  external_event_id VARCHAR(500) NOT NULL,  -- Google: event_id, Outlook: id
  title TEXT NOT NULL,
  description TEXT,
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  attendees TEXT,  -- JSON array
  is_all_day BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(connected_account_id, external_event_id)
);

-- Job logs (for debugging)
CREATE TABLE job_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_type VARCHAR(100),  -- 'fetch_emails', 'fetch_calendar', 'send_email'
  connected_account_id UUID REFERENCES connected_accounts(id) ON DELETE SET NULL,
  status VARCHAR(50),  -- 'PENDING', 'RUNNING', 'COMPLETED', 'FAILED'
  error_message TEXT,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Refresh tokens (for OAuth, separate table like Twenty)
CREATE TABLE oauth_refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_type VARCHAR(50),  -- 'login', 'workspace_agnostic'
  jwt_token TEXT NOT NULL,
  family VARCHAR(255),  -- For family-based refresh token rotation
  refresh_counter INT DEFAULT 0,
  is_revoked BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX(user_id)
);
```

**Step 2:** Migrate existing `oauth_connections`

```sql
-- Keep oauth_connections for backward compatibility
-- Add migration status column
ALTER TABLE oauth_connections ADD COLUMN migrated_at TIMESTAMP;

-- Create migration script to:
-- 1. Extract org_name from oauth_connections
-- 2. Create users based on org_name
-- 3. Create connected_accounts with tokens
-- 4. Mark as migrated
```

**Step 3:** Run migrations

```bash
# Using Alembic (Python)
alembic revision --autogenerate -m "add_dual_oauth_schema"
alembic upgrade head

# OR manually run SQL above
```

---

### Phase 2: Backend Implementation (Week 1-2)

#### 2.1 Create Authentication Endpoints

**File:** `backend/auth/routes.py` (NEW)

```python
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
import jwt
import uuid
from datetime import datetime, timedelta
from authlib.integrations.starlette_client import OAuth
import bcrypt

router = APIRouter(prefix="/auth", tags=["auth"])

# Initialize OAuth
oauth = OAuth()

# Register Google OAuth
oauth.register(
    name='google',
    client_id=os.getenv('AUTH_GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('AUTH_GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'  # ← MINIMAL for login
    }
)

# Register Microsoft OAuth
oauth.register(
    name='microsoft',
    client_id=os.getenv('AUTH_MICROSOFT_CLIENT_ID'),
    client_secret=os.getenv('AUTH_MICROSOFT_CLIENT_SECRET'),
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'  # ← MINIMAL for login
    }
)

@router.get('/login/google')
async def login_google(request: Request):
    """
    Flow 1: Start Google OAuth for LOGIN only
    Redirects to Google consent page with MINIMAL scopes
    """
    redirect_uri = request.url_for('login_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/login/google/callback')
async def login_google_callback(request: Request, db = Depends(get_db)):
    """
    Callback after Google approves login
    Creates/retrieves user and issues JWT tokens
    """
    try:
        token = await oauth.google.authorize_access_token(request)
        user_data = token.get('userinfo')

        if not user_data:
            raise HTTPException(status_code=400, detail="Failed to get user info")

        email = user_data.get('email')
        first_name = user_data.get('given_name')
        last_name = user_data.get('family_name')

        # Find or create user
        user = db.query(User).filter(User.email == email).first()

        if not user:
            # Create new user (if signup allowed)
            user = User(
                id=str(uuid.uuid4()),
                email=email,
                first_name=first_name,
                last_name=last_name,
                auth_provider='google',
                is_email_verified=True,  # Google has verified email
                email_verified_at=datetime.utcnow()
            )
            db.add(user)
            db.commit()

        # Generate JWT LoginToken (short-lived)
        login_token = generate_login_token(user.id, user.email)

        # Generate RefreshToken (long-lived, stored in DB)
        refresh_token = generate_refresh_token(user.id, token_type='login')

        # Redirect to frontend with tokens
        return RedirectResponse(
            url=f"http://localhost:3000/auth/callback?loginToken={login_token}&refreshToken={refresh_token}"
        )

    except Exception as e:
        return RedirectResponse(
            url=f"http://localhost:3000/auth/error?message={str(e)}"
        )

@router.get('/login/microsoft')
async def login_microsoft(request: Request):
    """
    Flow 1: Start Microsoft OAuth for LOGIN only
    Redirects to Microsoft consent page with MINIMAL scopes
    """
    redirect_uri = request.url_for('login_microsoft_callback')
    return await oauth.microsoft.authorize_redirect(request, redirect_uri)

@router.get('/login/microsoft/callback')
async def login_microsoft_callback(request: Request, db = Depends(get_db)):
    """
    Callback after Microsoft approves login
    (Similar to Google callback, see above)
    """
    # ... similar implementation to Google
    pass

@router.post('/logout')
async def logout(current_user: User = Depends(get_current_user), db = Depends(get_db)):
    """
    Logout: Revoke all refresh tokens for user
    """
    refresh_tokens = db.query(OAuthRefreshToken).filter(
        OAuthRefreshToken.user_id == current_user.id
    ).all()

    for token in refresh_tokens:
        token.is_revoked = True

    db.commit()

    return {"message": "Logged out successfully"}

@router.post('/refresh-token')
async def refresh_login_token(request: Request, db = Depends(get_db)):
    """
    Frontend calls this to get new LoginToken using RefreshToken
    """
    try:
        refresh_token = request.headers.get('Authorization', '').replace('Bearer ', '')

        # Verify refresh token JWT
        payload = jwt.decode(
            refresh_token,
            os.getenv('JWT_SECRET'),
            algorithms=['HS256']
        )

        # Check if token is revoked in DB
        token_record = db.query(OAuthRefreshToken).filter(
            OAuthRefreshToken.id == payload['jti'],
            OAuthRefreshToken.is_revoked == False
        ).first()

        if not token_record:
            raise HTTPException(status_code=401, detail="Token revoked")

        # Generate new LoginToken
        new_login_token = generate_login_token(
            payload['user_id'],
            payload['email']
        )

        return {
            "loginToken": new_login_token,
            "expiresIn": 900  # 15 minutes
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def generate_login_token(user_id: str, email: str) -> str:
    """
    Generate short-lived JWT LoginToken
    """
    payload = {
        'user_id': user_id,
        'email': email,
        'type': 'login',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=15)
    }

    return jwt.encode(
        payload,
        os.getenv('JWT_SECRET'),
        algorithm='HS256'
    )


def generate_refresh_token(user_id: str, token_type: str = 'login') -> str:
    """
    Generate long-lived JWT RefreshToken (stored in DB)
    """
    token_id = str(uuid.uuid4())

    payload = {
        'user_id': user_id,
        'type': 'refresh',
        'jti': token_id,  # JWT ID for revocation
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=7)
    }

    token = jwt.encode(
        payload,
        os.getenv('JWT_SECRET'),
        algorithm='HS256'
    )

    # Store in database for revocation checking
    db.add(OAuthRefreshToken(
        id=token_id,
        user_id=user_id,
        token_type=token_type,
        jwt_token=token,
        expires_at=payload['exp']
    ))
    db.commit()

    return token
```

#### 2.2 Create APIs OAuth Endpoints

**File:** `backend/auth/apis_routes.py` (NEW)

```python
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
import uuid
from datetime import datetime

router = APIRouter(prefix="/auth/apis", tags=["auth_apis"])

# Register OAuth with BROAD scopes
oauth.register(
    name='google_apis',
    client_id=os.getenv('AUTH_GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('AUTH_GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        # BROAD scopes for email/calendar access
        'scope': 'openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/calendar.readonly'
    }
)

oauth.register(
    name='microsoft_apis',
    client_id=os.getenv('AUTH_MICROSOFT_CLIENT_ID'),
    client_secret=os.getenv('AUTH_MICROSOFT_CLIENT_SECRET'),
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    client_kwargs={
        # BROAD scopes for email/calendar access
        'scope': 'openid email profile offline_access Mail.Send Mail.Read Calendars.Read'
    }
)

@router.get('/connect/google')
async def connect_google(request: Request, current_user: User = Depends(get_current_user)):
    """
    Flow 2: User clicks "Connect Gmail"
    Redirects to Google consent with BROAD scopes
    """
    # Store user info in session to retrieve later
    request.session['temp_user_id'] = current_user.id

    redirect_uri = request.url_for('connect_google_callback')
    return await oauth.google_apis.authorize_redirect(request, redirect_uri)

@router.get('/connect/google/callback')
async def connect_google_callback(request: Request, db = Depends(get_db)):
    """
    Callback after user approves Gmail/Calendar access
    """
    try:
        # Get OAuth tokens (with BROAD scopes now)
        token = await oauth.google_apis.authorize_access_token(request)
        user_data = token.get('userinfo')

        user_id = request.session.get('temp_user_id')
        email = user_data.get('email')

        # Save connected account with API tokens
        connected_account = ConnectedAccount(
            id=str(uuid.uuid4()),
            user_id=user_id,
            provider='google',
            email=email,
            access_token=encrypt_token(token['access_token']),
            refresh_token=encrypt_token(token.get('refresh_token')),
            token_expires_at=datetime.utcfromtimestamp(token['expires_at']),
            scope=token.get('scope'),
            is_active=True
        )

        db.add(connected_account)

        # Create sync status tracker
        sync_status = EmailSyncStatus(
            id=str(uuid.uuid4()),
            connected_account_id=connected_account.id,
            sync_status='PENDING',
            sync_stage='INITIAL'
        )

        db.add(sync_status)
        db.commit()

        # Queue background jobs to sync
        queue_job('fetch_emails_job', {
            'connected_account_id': connected_account.id,
            'user_id': user_id
        })

        queue_job('fetch_calendar_job', {
            'connected_account_id': connected_account.id,
            'user_id': user_id
        })

        return RedirectResponse(url="http://localhost:3000/settings?status=connected")

    except Exception as e:
        return RedirectResponse(url=f"http://localhost:3000/settings?error={str(e)}")

@router.post('/disconnect/google')
async def disconnect_google(current_user: User = Depends(get_current_user), db = Depends(get_db)):
    """
    User clicks "Disconnect Gmail"
    """
    # Mark as inactive
    connected_account = db.query(ConnectedAccount).filter(
        ConnectedAccount.user_id == current_user.id,
        ConnectedAccount.provider == 'google'
    ).first()

    if connected_account:
        connected_account.is_active = False

        # Delete synced data
        db.query(SyncedMessage).filter(
            SyncedMessage.connected_account_id == connected_account.id
        ).delete()

        db.query(CalendarEvent).filter(
            CalendarEvent.connected_account_id == connected_account.id
        ).delete()

        db.commit()

    return {"message": "Disconnected successfully"}
```

#### 2.3 Create Background Jobs

**File:** `backend/jobs/email_jobs.py` (NEW)

```python
from celery import Celery
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from datetime import datetime
import base64

celery_app = Celery('email_poc', broker='redis://localhost:6379')

@celery_app.task(name='fetch_emails_job')
def fetch_emails(connected_account_id: str, user_id: str):
    """
    Background job to fetch all emails from Gmail API
    """
    try:
        db = get_db()

        # Get connected account
        account = db.query(ConnectedAccount).filter(
            ConnectedAccount.id == connected_account_id
        ).first()

        if not account or not account.is_active:
            return

        # Decrypt tokens
        access_token = decrypt_token(account.access_token)
        refresh_token = decrypt_token(account.refresh_token)

        # Create credentials object
        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=os.getenv('AUTH_GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('AUTH_GOOGLE_CLIENT_SECRET')
        )

        # Refresh if expired
        if credentials.expired:
            credentials.refresh(Request())
            account.access_token = encrypt_token(credentials.token)
            account.token_expires_at = datetime.utcfromtimestamp(credentials.expiry.timestamp())
            db.commit()

        # Build Gmail service
        service = build('gmail', 'v1', credentials=credentials)

        # Update sync status
        sync_status = db.query(EmailSyncStatus).filter(
            EmailSyncStatus.connected_account_id == connected_account_id
        ).first()

        sync_status.sync_status = 'IN_PROGRESS'
        sync_status.last_sync_at = datetime.utcnow()
        db.commit()

        # Fetch messages
        page_token = None
        fetched_count = 0

        try:
            while True:
                results = service.users().messages().list(
                    userId='me',
                    pageToken=page_token,
                    maxResults=100
                ).execute()

                messages = results.get('messages', [])

                for msg in messages:
                    # Get full message details
                    message = service.users().messages().get(
                        userId='me',
                        id=msg['id']
                    ).execute()

                    # Parse message
                    headers = message['payload']['headers']
                    email_data = {
                        'connected_account_id': connected_account_id,
                        'external_message_id': msg['id'],
                        'subject': next((h['value'] for h in headers if h['name'] == 'Subject'), ''),
                        'from_email': next((h['value'] for h in headers if h['name'] == 'From'), ''),
                        'to_email': next((h['value'] for h in headers if h['name'] == 'To'), ''),
                        'received_at': datetime.utcfromtimestamp(int(message['internalDate']) / 1000)
                    }

                    # Check if already synced
                    existing = db.query(SyncedMessage).filter(
                        SyncedMessage.external_message_id == msg['id'],
                        SyncedMessage.connected_account_id == connected_account_id
                    ).first()

                    if not existing:
                        synced_msg = SyncedMessage(**email_data)
                        db.add(synced_msg)
                        fetched_count += 1

                db.commit()

                page_token = results.get('nextPageToken')
                if not page_token:
                    break

        except Exception as e:
            sync_status.sync_status = 'FAILED'
            sync_status.error_message = str(e)
            db.commit()
            raise

        # Mark as completed
        sync_status.sync_status = 'COMPLETED'
        sync_status.sync_stage = 'INCREMENTAL'
        sync_status.synced_messages_count = fetched_count
        db.commit()

        print(f"✅ Fetched {fetched_count} emails for {account.email}")

    except Exception as e:
        print(f"❌ Error fetching emails: {e}")
        raise

@celery_app.task(name='fetch_calendar_job')
def fetch_calendar(connected_account_id: str, user_id: str):
    """
    Background job to fetch calendar events from Google Calendar API
    """
    try:
        db = get_db()
        account = db.query(ConnectedAccount).filter(
            ConnectedAccount.id == connected_account_id
        ).first()

        if not account or not account.is_active:
            return

        # Similar to email fetching but for calendar
        access_token = decrypt_token(account.access_token)
        refresh_token = decrypt_token(account.refresh_token)

        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=os.getenv('AUTH_GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('AUTH_GOOGLE_CLIENT_SECRET')
        )

        if credentials.expired:
            credentials.refresh(Request())
            account.access_token = encrypt_token(credentials.token)
            db.commit()

        # Build Calendar service
        service = build('calendar', 'v3', credentials=credentials)

        # Fetch calendar events
        events = service.events().list(
            calendarId='primary',
            maxResults=50
        ).execute()

        for event in events.get('items', []):
            # Parse and store...
            pass

        print(f"✅ Fetched calendar events for {account.email}")

    except Exception as e:
        print(f"❌ Error fetching calendar: {e}")
        raise
```

#### 2.4 Token Encryption/Decryption

**File:** `backend/utils/encryption.py` (NEW)

```python
from cryptography.fernet import Fernet
import os

# Load encryption key (rotate this in production)
encryption_key = os.getenv('ENCRYPTION_KEY')
if not encryption_key:
    raise ValueError("ENCRYPTION_KEY not set in environment")

cipher = Fernet(encryption_key.encode())

def encrypt_token(token: str) -> str:
    """
    Encrypt OAuth token before storing in DB
    """
    return cipher.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    """
    Decrypt OAuth token when retrieving from DB
    """
    return cipher.decrypt(encrypted_token.encode()).decode()
```

#### 2.5 Update Main API File

**File:** `backend/main.py` (MODIFY)

```python
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi_sessions.backends.implementations import SessionBackend
from fastapi_sessions.session_verifier import SessionVerifier
from auth.routes import router as auth_router
from auth.apis_routes import router as apis_router
from api.email_routes import router as email_router
from api.calendar_routes import router as calendar_router
from api.sync_status_routes import router as sync_router

app = FastAPI(title="Email POC - Enhanced with OAuth")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session management
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SESSION_SECRET'))

# Include routers
app.include_router(auth_router)
app.include_router(apis_router)
app.include_router(email_router)
app.include_router(calendar_router)
app.include_router(sync_router)

@app.get('/health')
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

### Phase 3: Frontend Implementation (Week 2)

#### 3.1 Create State Management

**File:** `frontend/src/atoms/authAtoms.js` (NEW)

```javascript
import { atom } from 'recoil';

// User state
export const currentUserAtom = atom({
  key: 'currentUser',
  default: null,
});

// Login token (short-lived)
export const loginTokenAtom = atom({
  key: 'loginToken',
  default: null,
});

// Refresh token (long-lived)
export const refreshTokenAtom = atom({
  key: 'refreshToken',
  default: null,
});

// Connected accounts
export const connectedAccountsAtom = atom({
  key: 'connectedAccounts',
  default: [],
});

// Sync status
export const syncStatusAtom = atom({
  key: 'syncStatus',
  default: {
    emailSync: 'IDLE',
    calendarSync: 'IDLE',
    lastSyncAt: null,
    emailCount: 0,
    eventCount: 0,
  },
});

// Authentication error
export const authErrorAtom = atom({
  key: 'authError',
  default: null,
});
```

#### 3.2 Create Authentication Hooks

**File:** `frontend/src/hooks/useAuth.js` (NEW)

```javascript
import { useRecoilState } from 'recoil';
import { useCallback } from 'react';
import axios from 'axios';
import jwtDecode from 'jwt-decode';
import {
  currentUserAtom,
  loginTokenAtom,
  refreshTokenAtom,
  authErrorAtom,
} from '../atoms/authAtoms';

export const useAuth = () => {
  const [currentUser, setCurrentUser] = useRecoilState(currentUserAtom);
  const [loginToken, setLoginToken] = useRecoilState(loginTokenAtom);
  const [refreshToken, setRefreshToken] = useRecoilState(refreshTokenAtom);
  const [authError, setAuthError] = useRecoilState(authErrorAtom);

  // Initialize auth from localStorage
  const initializeAuth = useCallback(() => {
    const savedLoginToken = localStorage.getItem('loginToken');
    const savedRefreshToken = localStorage.getItem('refreshToken');
    const savedUser = localStorage.getItem('currentUser');

    if (savedLoginToken && savedUser) {
      setLoginToken(savedLoginToken);
      setRefreshToken(savedRefreshToken);
      setCurrentUser(JSON.parse(savedUser));
    }
  }, []);

  // Save auth tokens
  const saveTokens = useCallback((login, refresh, user) => {
    localStorage.setItem('loginToken', login);
    localStorage.setItem('refreshToken', refresh);
    localStorage.setItem('currentUser', JSON.stringify(user));

    setLoginToken(login);
    setRefreshToken(refresh);
    setCurrentUser(user);
  }, []);

  // Check if token is expired
  const isTokenExpired = useCallback((token) => {
    try {
      const decoded = jwtDecode(token);
      return decoded.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }, []);

  // Refresh login token
  const refreshLoginToken = useCallback(async () => {
    try {
      const response = await axios.post('http://localhost:8000/auth/refresh-token', {}, {
        headers: {
          'Authorization': `Bearer ${refreshToken}`
        }
      });

      const newLoginToken = response.data.loginToken;
      setLoginToken(newLoginToken);
      localStorage.setItem('loginToken', newLoginToken);

      return newLoginToken;
    } catch (error) {
      setAuthError('Token refresh failed');
      logout();
      throw error;
    }
  }, [refreshToken]);

  // Get valid login token (refresh if needed)
  const getValidLoginToken = useCallback(async () => {
    if (!loginToken) return null;

    if (isTokenExpired(loginToken)) {
      return await refreshLoginToken();
    }

    return loginToken;
  }, [loginToken, isTokenExpired, refreshLoginToken]);

  // Login with Google
  const loginWithGoogle = useCallback(() => {
    window.location.href = 'http://localhost:8000/auth/login/google';
  }, []);

  // Login with Microsoft
  const loginWithMicrosoft = useCallback(() => {
    window.location.href = 'http://localhost:8000/auth/login/microsoft';
  }, []);

  // Process login callback
  const processLoginCallback = useCallback((params) => {
    const loginToken = params.get('loginToken');
    const refreshToken = params.get('refreshToken');

    if (loginToken && refreshToken) {
      try {
        const decoded = jwtDecode(loginToken);
        const user = {
          userId: decoded.user_id,
          email: decoded.email,
        };

        saveTokens(loginToken, refreshToken, user);
        setAuthError(null);
        return true;
      } catch (error) {
        setAuthError('Invalid token');
        return false;
      }
    }

    return false;
  }, [saveTokens]);

  // Logout
  const logout = useCallback(async () => {
    try {
      await axios.post('http://localhost:8000/auth/logout', {}, {
        headers: {
          'Authorization': `Bearer ${loginToken}`
        }
      });
    } catch (error) {
      console.error('Logout error:', error);
    }

    localStorage.removeItem('loginToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('currentUser');

    setLoginToken(null);
    setRefreshToken(null);
    setCurrentUser(null);
  }, [loginToken]);

  return {
    currentUser,
    loginToken,
    refreshToken,
    authError,
    isAuthenticated: !!currentUser,
    initializeAuth,
    loginWithGoogle,
    loginWithMicrosoft,
    processLoginCallback,
    logout,
    getValidLoginToken,
    refreshLoginToken,
  };
};
```

#### 3.3 Create Connected Accounts Hook

**File:** `frontend/src/hooks/useConnectedAccounts.js` (NEW)

```javascript
import { useRecoilState } from 'recoil';
import { useCallback } from 'react';
import axios from 'axios';
import { connectedAccountsAtom, syncStatusAtom } from '../atoms/authAtoms';
import { useAuth } from './useAuth';

export const useConnectedAccounts = () => {
  const [connectedAccounts, setConnectedAccounts] = useRecoilState(connectedAccountsAtom);
  const [syncStatus, setSyncStatus] = useRecoilState(syncStatusAtom);
  const { getValidLoginToken } = useAuth();

  // Fetch connected accounts
  const fetchConnectedAccounts = useCallback(async () => {
    try {
      const token = await getValidLoginToken();
      const response = await axios.get(
        'http://localhost:8000/api/connected-accounts',
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      setConnectedAccounts(response.data);
    } catch (error) {
      console.error('Failed to fetch connected accounts:', error);
    }
  }, [getValidLoginToken]);

  // Connect Google account
  const connectGoogle = useCallback(async () => {
    window.location.href = 'http://localhost:8000/auth/apis/connect/google';
  }, []);

  // Connect Microsoft account
  const connectMicrosoft = useCallback(async () => {
    window.location.href = 'http://localhost:8000/auth/apis/connect/microsoft';
  }, []);

  // Disconnect account
  const disconnectAccount = useCallback(async (provider) => {
    try {
      const token = await getValidLoginToken();
      await axios.post(
        `http://localhost:8000/auth/apis/disconnect/${provider}`,
        {},
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      await fetchConnectedAccounts();
    } catch (error) {
      console.error('Disconnect failed:', error);
    }
  }, [getValidLoginToken, fetchConnectedAccounts]);

  // Fetch sync status
  const fetchSyncStatus = useCallback(async () => {
    try {
      const token = await getValidLoginToken();
      const response = await axios.get(
        'http://localhost:8000/api/sync-status',
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      setSyncStatus(response.data);
    } catch (error) {
      console.error('Failed to fetch sync status:', error);
    }
  }, [getValidLoginToken]);

  return {
    connectedAccounts,
    syncStatus,
    fetchConnectedAccounts,
    connectGoogle,
    connectMicrosoft,
    disconnectAccount,
    fetchSyncStatus,
  };
};
```

#### 3.4 Update Email Page Component

**File:** `frontend/src/pages/Email.js` (MODIFY)

```javascript
import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useConnectedAccounts } from '../hooks/useConnectedAccounts';
import AuthPage from './Auth';
import EmailDashboard from '../components/EmailDashboard';
import ConnectedAccountsPanel from '../components/ConnectedAccountsPanel';

export const EmailPage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const {
    currentUser,
    isAuthenticated,
    initializeAuth,
    processLoginCallback,
    loginWithGoogle,
    loginWithMicrosoft,
    logout,
  } = useAuth();

  const {
    connectedAccounts,
    syncStatus,
    fetchConnectedAccounts,
    connectGoogle,
    connectMicrosoft,
    disconnectAccount,
    fetchSyncStatus,
  } = useConnectedAccounts();

  // Initialize auth on mount
  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);

  // Process OAuth callback
  useEffect(() => {
    if (searchParams.has('loginToken')) {
      const success = processLoginCallback(searchParams);
      if (success) {
        navigate('/');
      }
    }
  }, [searchParams, processLoginCallback, navigate]);

  // Fetch data when authenticated
  useEffect(() => {
    if (isAuthenticated) {
      fetchConnectedAccounts();
      // Poll sync status every 5 seconds
      const interval = setInterval(fetchSyncStatus, 5000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated, fetchConnectedAccounts, fetchSyncStatus]);

  if (!isAuthenticated) {
    return (
      <AuthPage
        onGoogleLogin={loginWithGoogle}
        onMicrosoftLogin={loginWithMicrosoft}
      />
    );
  }

  return (
    <div className="email-page">
      <div className="header">
        <h1>Email & Calendar Hub</h1>
        <div className="user-info">
          <span>{currentUser.email}</span>
          <button onClick={logout}>Logout</button>
        </div>
      </div>

      <div className="content">
        <ConnectedAccountsPanel
          accounts={connectedAccounts}
          syncStatus={syncStatus}
          onConnectGoogle={connectGoogle}
          onConnectMicrosoft={connectMicrosoft}
          onDisconnect={disconnectAccount}
        />

        <EmailDashboard
          emails={syncStatus.emails}
          events={syncStatus.events}
          syncStatus={syncStatus}
        />
      </div>
    </div>
  );
};

export default EmailPage;
```

#### 3.5 Create Auth Callback Page

**File:** `frontend/src/pages/AuthCallback.js` (NEW)

```javascript
import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { processLoginCallback } = useAuth();

  useEffect(() => {
    const loginToken = searchParams.get('loginToken');
    const refreshToken = searchParams.get('refreshToken');

    if (loginToken && refreshToken) {
      try {
        processLoginCallback(searchParams);
        navigate('/');
      } catch (error) {
        navigate('/?error=auth_failed');
      }
    }
  }, [searchParams, navigate, processLoginCallback]);

  return (
    <div className="auth-loading">
      <p>Authenticating...</p>
    </div>
  );
};

export default AuthCallback;
```

---

### Phase 4: Environment Setup (Week 2)

#### 4.1 Create .env File

**File:** `backend/.env`

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/email_poc

# Redis
REDIS_URL=redis://localhost:6379

# OAuth - Google
AUTH_GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
AUTH_GOOGLE_CLIENT_SECRET=your_client_secret
AUTH_GOOGLE_CALLBACK_URL=http://localhost:8000/auth/login/google/callback
AUTH_GOOGLE_APIS_CALLBACK_URL=http://localhost:8000/auth/apis/connect/google/callback

# OAuth - Microsoft
AUTH_MICROSOFT_CLIENT_ID=your_client_id
AUTH_MICROSOFT_CLIENT_SECRET=your_client_secret
AUTH_MICROSOFT_CALLBACK_URL=http://localhost:8000/auth/login/microsoft/callback
AUTH_MICROSOFT_APIS_CALLBACK_URL=http://localhost:8000/auth/apis/connect/microsoft/callback

# JWT
JWT_SECRET=your_jwt_secret_key_change_in_production
SESSION_SECRET=your_session_secret_key

# Encryption
ENCRYPTION_KEY=your_encryption_key_base64_encoded

# Frontend
FRONTEND_URL=http://localhost:3000

# Environment
NODE_ENV=development
```

#### 4.2 Docker Compose for Local Development

**File:** `docker-compose.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: email_poc
      POSTGRES_PASSWORD: password
      POSTGRES_DB: email_poc
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7
    ports:
      - "6379:6379"

  celery_worker:
    build: .
    command: celery -A jobs worker -l info
    depends_on:
      - redis
      - postgres
    environment:
      - DATABASE_URL=postgresql://email_poc:password@postgres:5432/email_poc
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./backend:/app/backend

volumes:
  postgres_data:
```

---

### Phase 5: Security Enhancements (Week 3)

#### 5.1 Token Rotation

**File:** `backend/auth/token_rotation.py` (NEW)

```python
from datetime import datetime, timedelta
import uuid

async def rotate_refresh_token(user_id: str, old_token_id: str, db):
    """
    Implement refresh token rotation for security
    - Family-based approach: Group related tokens
    - Detect reuse attacks
    """
    # Create new refresh token
    new_token_id = str(uuid.uuid4())
    new_payload = {
        'user_id': user_id,
        'type': 'refresh',
        'jti': new_token_id,
        'family': old_token_id,  # Group in family
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=7)
    }

    new_token = jwt.encode(new_payload, os.getenv('JWT_SECRET'), algorithm='HS256')

    # Mark old token as rotated
    old_token = db.query(OAuthRefreshToken).filter(
        OAuthRefreshToken.id == old_token_id
    ).first()

    if old_token:
        old_token.is_rotated = True

    # Save new token
    db.add(OAuthRefreshToken(
        id=new_token_id,
        user_id=user_id,
        jwt_token=new_token,
        family=old_token_id,
        expires_at=new_payload['exp']
    ))

    db.commit()

    return new_token
```

#### 5.2 Rate Limiting

**File:** `backend/middleware/rate_limit.py` (NEW)

```python
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.util import get_remote_address
import redis

async def startup_rate_limiter():
    """Initialize rate limiter with Redis backend"""
    redis_client = redis.Redis(url=os.getenv('REDIS_URL'))
    await FastAPILimiter.init(redis_client, key_builder=get_remote_address)

# Apply to auth endpoints
@auth_router.post('/refresh-token')
@limiter.limit("10/minute")  # Max 10 refreshes per minute
async def refresh_token_with_limit(request: Request):
    ...
```

#### 5.3 CORS & CSRF

**File:** `backend/security/csrf.py` (NEW)

```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.csrf import CSRFMiddleware

# Already done in main.py, but ensure:

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Whitelist only frontend
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)

# For production, add CSRF middleware
if os.getenv('NODE_ENV') == 'production':
    app.add_middleware(CSRFMiddleware, secret_key=os.getenv('CSRF_SECRET'))
```

---

### Phase 6: Testing & Deployment (Week 3)

#### 6.1 Unit Tests

**File:** `backend/tests/test_auth.py` (NEW)

```python
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_login_google_callback():
    """Test Google login callback"""
    response = client.get(
        '/auth/login/google/callback?code=test_code&state=test_state'
    )
    assert response.status_code == 307  # Redirect

def test_refresh_token():
    """Test token refresh"""
    refresh_token = "test_refresh_token"
    response = client.post(
        '/auth/refresh-token',
        headers={'Authorization': f'Bearer {refresh_token}'}
    )
    assert response.status_code in [200, 401]

def test_connect_google_api():
    """Test connecting Gmail API"""
    response = client.get('/auth/apis/connect/google')
    assert response.status_code == 307

def test_disconnect_account():
    """Test disconnecting account"""
    response = client.post(
        '/auth/apis/disconnect/google',
        headers={'Authorization': 'Bearer test_token'}
    )
    assert response.status_code in [200, 401]
```

#### 6.2 Integration Tests

**File:** `backend/tests/test_integration.py` (NEW)

```python
@pytest.mark.asyncio
async def test_full_login_and_connect_flow():
    """Test complete flow: login -> connect account -> sync emails"""
    # 1. Simulate Google login
    # 2. Create user
    # 3. Create session
    # 4. Connect Gmail
    # 5. Verify emails synced
    pass

@pytest.mark.asyncio
async def test_token_refresh():
    """Test token refresh flow"""
    # 1. Create user with tokens
    # 2. Wait for token expiry
    # 3. Refresh token
    # 4. Verify new token works
    pass

@pytest.mark.asyncio
async def test_disconnect_cleanup():
    """Test disconnecting account cleans up data"""
    # 1. Connect account
    # 2. Sync emails
    # 3. Disconnect
    # 4. Verify synced emails deleted
    pass
```

#### 6.3 Deployment Checklist

```markdown
## Pre-Production Checklist

### Backend
- [ ] Set production encryption key
- [ ] Enable HTTPS only
- [ ] Configure CORS for production frontend URL
- [ ] Set DATABASE_URL to production database
- [ ] Set REDIS_URL to production Redis
- [ ] Enable rate limiting
- [ ] Configure CSRF protection
- [ ] Set up SSL/TLS certificates
- [ ] Configure reverse proxy (nginx)
- [ ] Setup monitoring (Sentry, DataDog)
- [ ] Configure logging to centralized service
- [ ] Set up database backups
- [ ] Create database indexes for performance
- [ ] Test OAuth apps with production URLs

### Frontend
- [ ] Update API_BASE_URL to production backend
- [ ] Set OAuth callback URLs to production domain
- [ ] Enable service worker for caching
- [ ] Configure CDN for static assets
- [ ] Set security headers (CSP, X-Frame-Options)
- [ ] Enable gzip compression
- [ ] Configure error reporting (Sentry)

### Infrastructure
- [ ] Setup Docker images for all services
- [ ] Configure Kubernetes/ECS for orchestration
- [ ] Setup CI/CD pipeline (GitHub Actions)
- [ ] Configure load balancing
- [ ] Setup auto-scaling
- [ ] Configure alerting
- [ ] Create disaster recovery plan
- [ ] Document API endpoints
- [ ] Create user documentation
```

---

## Database Schema Modifications

### Create Migration Script

**File:** `backend/migrations/add_dual_oauth_schema.sql`

```sql
-- Run this after Phase 1 setup

-- Create users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  auth_provider VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_email_verified BOOLEAN DEFAULT FALSE,
  email_verified_at TIMESTAMP,
  CONSTRAINT valid_provider CHECK (
    auth_provider IN ('password', 'google', 'microsoft', 'sso')
  )
);

-- Create connected_accounts table
CREATE TABLE connected_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,
  email VARCHAR(255) NOT NULL,
  access_token TEXT NOT NULL,
  refresh_token TEXT,
  token_expires_at TIMESTAMP,
  scope TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_refresh_at TIMESTAMP,
  UNIQUE(user_id, provider),
  CONSTRAINT valid_provider CHECK (provider IN ('google', 'microsoft'))
);

-- Create email_sync_status table
CREATE TABLE email_sync_status (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connected_account_id UUID NOT NULL UNIQUE REFERENCES connected_accounts(id) ON DELETE CASCADE,
  sync_status VARCHAR(50) DEFAULT 'PENDING',
  sync_stage VARCHAR(50),
  last_sync_at TIMESTAMP,
  next_sync_at TIMESTAMP,
  error_message TEXT,
  synced_messages_count INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_status CHECK (
    sync_status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'PAUSED')
  )
);

-- Create synced_messages table
CREATE TABLE synced_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connected_account_id UUID NOT NULL REFERENCES connected_accounts(id) ON DELETE CASCADE,
  external_message_id VARCHAR(500) NOT NULL,
  subject TEXT,
  body TEXT,
  from_email VARCHAR(255),
  to_email VARCHAR(255),
  cc TEXT,
  bcc TEXT,
  received_at TIMESTAMP,
  is_read BOOLEAN DEFAULT FALSE,
  labels TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(connected_account_id, external_message_id)
);

-- Create calendar_events table
CREATE TABLE calendar_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connected_account_id UUID NOT NULL REFERENCES connected_accounts(id) ON DELETE CASCADE,
  external_event_id VARCHAR(500) NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  attendees TEXT,
  is_all_day BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(connected_account_id, external_event_id)
);

-- Create oauth_refresh_tokens table
CREATE TABLE oauth_refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_type VARCHAR(50),
  jwt_token TEXT NOT NULL,
  family VARCHAR(255),
  refresh_counter INT DEFAULT 0,
  is_revoked BOOLEAN DEFAULT FALSE,
  is_rotated BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create job_logs table
CREATE TABLE job_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_type VARCHAR(100),
  connected_account_id UUID REFERENCES connected_accounts(id) ON DELETE SET NULL,
  status VARCHAR(50),
  error_message TEXT,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_auth_provider ON users(auth_provider);
CREATE INDEX idx_connected_accounts_user_id ON connected_accounts(user_id);
CREATE INDEX idx_connected_accounts_provider ON connected_accounts(provider);
CREATE INDEX idx_synced_messages_account ON synced_messages(connected_account_id);
CREATE INDEX idx_synced_messages_received ON synced_messages(received_at);
CREATE INDEX idx_calendar_events_account ON calendar_events(connected_account_id);
CREATE INDEX idx_calendar_events_time ON calendar_events(start_time);
CREATE INDEX idx_oauth_tokens_user ON oauth_refresh_tokens(user_id);
CREATE INDEX idx_email_sync_status_account ON email_sync_status(connected_account_id);

-- Create triggers for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_connected_accounts_updated_at BEFORE UPDATE ON connected_accounts
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_synced_messages_updated_at BEFORE UPDATE ON synced_messages
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_calendar_events_updated_at BEFORE UPDATE ON calendar_events
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_email_sync_status_updated_at BEFORE UPDATE ON email_sync_status
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

---

## Implementation Timeline Summary

```
WEEK 1 (Phase 1 + 2.1-2.3)
  Day 1: Setup database & install dependencies
  Day 2: Create authentication endpoints (login)
  Day 3: Create APIs OAuth endpoints (connect Gmail)
  Day 4: Create background jobs infrastructure
  Day 5: Token encryption & utility functions

WEEK 2 (Phase 2.4-2.5 + Phase 3)
  Day 6: Update main.py with new routes
  Day 7: Frontend state management (Recoil atoms)
  Day 8: Frontend auth hooks
  Day 9: Update Email page component
  Day 10: Create auth callback page

WEEK 3 (Phase 4-6)
  Day 11: Environment setup & Docker
  Day 12: Security enhancements (rotation, rate limiting)
  Day 13: Write unit & integration tests
  Day 14: Pre-production checklist & deployment prep
```

---

## Key Files to Modify/Create

### New Files Required

```
backend/
├── auth/
│   ├── __init__.py
│   ├── routes.py              (Phase 2.1)
│   ├── apis_routes.py         (Phase 2.2)
│   ├── token_rotation.py      (Phase 5.1)
│   └── models.py
├── jobs/
│   ├── __init__.py
│   ├── email_jobs.py          (Phase 2.3)
│   ├── calendar_jobs.py
│   └── tasks.py
├── utils/
│   ├── encryption.py          (Phase 2.4)
│   └── token.py
├── middleware/
│   ├── rate_limit.py          (Phase 5.2)
│   └── auth.py
├── security/
│   ├── csrf.py                (Phase 5.3)
│   └── cors.py
├── tests/
│   ├── test_auth.py           (Phase 6.1)
│   └── test_integration.py    (Phase 6.2)
├── migrations/
│   └── add_dual_oauth_schema.sql
├── models.py                  (UPDATE)
├── config.py                  (UPDATE)
└── main.py                    (UPDATE Phase 2.5)

frontend/
├── src/
│   ├── atoms/
│   │   └── authAtoms.js       (Phase 3.1)
│   ├── hooks/
│   │   ├── useAuth.js         (Phase 3.2)
│   │   └── useConnectedAccounts.js (Phase 3.3)
│   ├── pages/
│   │   ├── Email.js           (UPDATE Phase 3.4)
│   │   ├── AuthCallback.js    (Phase 3.5)
│   │   └── Auth.js
│   ├── components/
│   │   ├── ConnectedAccountsPanel.js
│   │   └── EmailDashboard.js
│   └── App.js                 (UPDATE routing)

docker-compose.yml            (Phase 4.2)
.env                          (Phase 4.1)
```

---

## Success Criteria

After implementation, you should have:

✅ **Two separate OAuth flows:**
- Flow 1: Login OAuth (users authenticate with Google/Microsoft)
- Flow 2: APIs OAuth (users connect Gmail/Outlook for syncing)

✅ **Database properly structured:**
- Separate tables for users, connected accounts, synced data
- Proper relationships and constraints
- Indexes for performance

✅ **Backend features:**
- JWT token generation & refresh
- Automatic token rotation
- Background jobs for syncing
- Proper error handling

✅ **Frontend features:**
- State management with Recoil
- Login flow with redirects
- Connected accounts panel
- Sync status display
- Logout functionality

✅ **Security:**
- HTTPS enforcement
- CORS configured
- Token encryption
- Rate limiting
- CSRF protection

✅ **Operational readiness:**
- Docker compose for local development
- Tests covering auth flows
- Deployment checklist
- Documentation

---

## Next Steps After Implementation

1. **User testing:** Let users test the flows
2. **Performance optimization:** Profile and optimize database queries
3. **Scalability:** Load test and optimize for multiple concurrent users
4. **Monitoring:** Setup application monitoring and alerting
5. **Documentation:** Create user guides and API documentation
6. **Mobile app:** Build native apps using the same backend
