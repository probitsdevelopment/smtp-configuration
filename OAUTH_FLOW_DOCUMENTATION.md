# OAuth 2.0 Flow Documentation: Twenty CRM vs Email POC

**Author:** Analysis Document
**Date:** February 18, 2026
**Status:** Comprehensive OAuth Flow Explanation

---

## Table of Contents

1. [Overview](#overview)
2. [OAuth 2.0 Fundamentals](#oauth-20-fundamentals)
3. [Twenty CRM OAuth Architecture](#twenty-crm-oauth-architecture)
4. [Google OAuth Flow in Twenty](#google-oauth-flow-in-twenty)
5. [Microsoft OAuth Flow in Twenty](#microsoft-oauth-flow-in-twenty)
6. [Comparison with Email POC](#comparison-with-email-poc)
7. [Security Considerations](#security-considerations)
8. [Token Management](#token-management)

---

## Overview

Twenty CRM implements **OAuth 2.0** authentication with a sophisticated dual-flow architecture:

1. **Login OAuth Flow** - Authenticate users into Twenty CRM (Google/Microsoft/OIDC)
2. **APIs OAuth Flow** - Grant access to Gmail API and Microsoft Graph API (for email/calendar sync)

This differs significantly from the Email POC, which uses a single, focused OAuth flow just to send emails.

---

## OAuth 2.0 Fundamentals

### What is OAuth 2.0?

OAuth 2.0 is an **authorization protocol** that allows users to grant third-party applications permission to access their resources on another service **without sharing passwords**.

### OAuth 2.0 Authorization Code Grant Flow

```
┌──────────┐                                    ┌──────────────┐
│  Client  │                                    │  Auth Server │
│ (Twenty) │                                    │  (Google)    │
└────┬─────┘                                    └──────┬───────┘
     │                                                 │
     ├──── 1. Redirect to Auth Server ──────────────→ │
     │        (with client_id, scopes, state)        │
     │                                                │
     │         [User sees consent screen]             │
     │         [User clicks "Allow"]                  │
     │                                                │
     │ ← ──── 2. Redirect back with code ──────────── ├
     │        (& state for CSRF validation)           │
     │                                                │
     ├──── 3. Exchange code for token ──────────────→ │
     │        (Backend to backend)                    │
     │        (with client_secret)                    │
     │                                                │
     │ ← ──── 4. Return access_token + user info ──── ├
     │                                                │
```

### Key Components

- **Authorization Code**: One-time code exchanged for tokens (valid ~10 min)
- **Access Token**: Used to access resources from the provider API
- **Refresh Token**: Long-lived token to get new access tokens
- **State Token**: CSRF protection - must match between request and callback
- **Scopes**: Permissions being requested (e.g., "read:emails", "send emails")

---

## Twenty CRM OAuth Architecture

### Supported Auth Providers

```typescript
enum AuthProviderEnum {
  Google = 'google',              // OAuth 2.0
  Microsoft = 'microsoft',        // OAuth 2.0
  Password = 'password',          // Email/password (not OAuth)
  SSO = 'sso',                    // OpenID Connect (OIDC)
  Impersonation = 'impersonation' // Admin feature
}
```

### Two Separate OAuth Flows

```
┌─────────────────────────────────────────────────────────────────┐
│              FLOW 1: LOGIN OAUTH (Authentication)               │
│                                                                 │
│  Scopes: 'email', 'profile' (MINIMAL)                           │
│  Purpose: Get user email & profile to log into Twenty           │
│  Result: Issue JWT tokens (LoginToken → AccessToken)            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│           FLOW 2: APIS OAUTH (Authorization)                    │
│                                                                 │
│  Scopes: 'gmail.send', 'calendar', 'messages' (BROAD)           │
│  Purpose: Get permission to access Gmail API & Graph API        │
│  Result: Store tokens in ConnectedAccount, sync emails/calendar │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture Diagram

```
                    ┌─────────────────────────┐
                    │   Twenty Frontend       │
                    └────────┬────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
        ┌───────▼────────┐      ┌────────▼─────────┐
        │ Login OAuth    │      │ APIs OAuth       │
        │ (Auth)         │      │ (Gmail/Outlook)  │
        └───────┬────────┘      └────────┬──────────┘
                │                        │
        ┌───────▼────────┐      ┌────────▼──────────────┐
        │ Google/MS      │      │ Google/MS OAuth       │
        │ OAuth Consent  │      │ Consent (Broad scope) │
        │ (Minimal)      │      │                       │
        └───────┬────────┘      └────────┬──────────────┘
                │                        │
        ┌───────▼────────┐      ┌────────▼──────────────┐
        │ JWT Tokens     │      │ Store in DB           │
        │ for Twenty     │      │ + APIs (Gmail/Graph)  │
        └────────────────┘      └───────────────────────┘
```

---

## Google OAuth Flow in Twenty

### Overview

Twenty CRM has **two separate Google OAuth strategies**:

1. **GoogleStrategy** - For login (scopes: email, profile)
2. **GoogleAPIsOauthCommonStrategy** - For API access (scopes: gmail.send, calendar)

### Flow 1: Google Login OAuth

#### Step-by-Step Process

```
1. USER CLICKS "SIGN IN WITH GOOGLE"
   │
   ├─ Frontend redirects to:
   │  GET /auth/google?workspace=...&action=...
   │
   ├─ Passport middleware intercepts request
   │
   └─ NestJS Guard: GoogleAuthGuard (from passport)

2. GOOGLE OAUTH CONSENT PAGE
   │
   ├─ User sees: "Twenty wants access to:"
   │  • Your email address
   │  • Your profile info
   │
   ├─ User clicks: "Allow"
   │
   └─ Browser redirected with authorization code

3. CALLBACK WITH AUTHORIZATION CODE
   │
   ├─ URL: GET /auth/google/callback?code=AUTH_CODE&state=STATE
   │
   ├─ Passport validates state (CSRF protection)
   │
   ├─ Passport exchanges code for tokens:
   │  POST https://oauth2.googleapis.com/token
   │  {
   │    code: AUTH_CODE,
   │    client_id: ...,
   │    client_secret: ...,
   │    redirect_uri: CALLBACK_URL,
   │    grant_type: 'authorization_code'
   │  }
   │
   ├─ Google responds:
   │  {
   │    access_token: '...',
   │    expires_in: 3600,
   │    refresh_token: '...',
   │    token_type: 'Bearer',
   │    id_token: '...'
   │  }
   │
   └─ Passport uses access_token to fetch user profile

4. VALIDATE AND EXTRACT USER INFO
   │
   ├─ GoogleStrategy.validate() is called
   │  (from packages/twenty-server/src/engine/core-modules/auth/strategies/google.auth.strategy.ts)
   │
   ├─ Extracts from Google profile:
   │  {
   │    email: 'user@example.com',
   │    firstName: 'John',
   │    lastName: 'Doe',
   │    picture: 'https://...'
   │  }
   │
   └─ Calls done(null, user)

5. CREATE/LOGIN USER IN TWENTY
   │
   ├─ Backend checks if user exists in PostgreSQL
   │
   ├─ If yes: Login existing user
   │  If no: Create new user (if signup allowed)
   │
   ├─ Checks workspace access
   │
   └─ Stores auth provider: 'google'

6. GENERATE JWT LOGIN TOKEN
   │
   ├─ Via LoginTokenService.generateLoginToken()
   │
   ├─ Creates JWT with payload:
   │  {
   │    type: 'LOGIN',
   │    sub: 'user@example.com',
   │    workspaceId: 'workspace_123',
   │    authProvider: 'google',
   │    iat: ...,
   │    exp: ... (15 minutes from now)
   │  }
   │
   ├─ Secret: Generated per workspace
   │  (via JwtWrapperService.generateAppSecret())
   │
   └─ Signed and returned to frontend

7. FRONTEND RECEIVES LOGIN TOKEN
   │
   ├─ Stored in Recoil state
   │
   ├─ Stored in browser cookies
   │
   └─ Can now exchange for full access tokens

8. EXCHANGE LOGIN TOKEN FOR ACCESS TOKENS
   │
   ├─ Frontend calls: getAuthTokensFromLoginToken(loginToken)
   │
   ├─ Backend validates LoginToken
   │
   ├─ Generates:
   │  • AccessToken (15 min expiry)
   │  • RefreshToken (7 days expiry, stored in DB)
   │
   └─ User is now FULLY authenticated
```

#### Code Example: Google Login Strategy

**File:** `packages/twenty-server/src/engine/core-modules/auth/strategies/google.auth.strategy.ts`

```typescript
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(twentyConfigService: TwentyConfigService) {
    super({
      clientID: twentyConfigService.get('AUTH_GOOGLE_CLIENT_ID'),
      clientSecret: twentyConfigService.get('AUTH_GOOGLE_CLIENT_SECRET'),
      callbackURL: twentyConfigService.get('AUTH_GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],  // ← MINIMAL scopes for login only
      passReqToCallback: true,
    });
  }

  // Passport calls this after exchanging authorization code
  async validate(
    request: GoogleRequest,
    _accessToken: string,      // Not used for login
    _refreshToken: string,      // Not used for login
    profile: any,
    done: VerifyCallback,
  ): Promise<void> {
    const { name, emails, photos } = profile;

    // Validate email is verified with Google
    const firstVerifiedEmail = emails.find(
      (email: { verified: boolean }) => email?.verified === true,
    )?.value;

    if (!firstVerifiedEmail) {
      throw new AuthException(
        'Please verify your email address with Google',
        AuthExceptionCode.EMAIL_NOT_VERIFIED,
      );
    }

    // Extract workspace context from state
    const state = JSON.parse(request.query.state);

    // Build user object
    const user: GoogleRequest['user'] = {
      email: firstVerifiedEmail,
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos?.[0]?.value,
      workspaceInviteHash: state.workspaceInviteHash,
      workspacePersonalInviteToken: state.workspacePersonalInviteToken,
      workspaceId: state.workspaceId,
      billingCheckoutSessionState: state.billingCheckoutSessionState,
      action: state.action,
      locale: state.locale,
    };

    // Pass to next middleware
    done(null, user);
  }
}
```

#### Passport Configuration

**File:** `packages/twenty-server/src/engine/core-modules/auth/auth.resolver.ts`

```typescript
// After user is validated by GoogleStrategy:
const user = await this.authService.validateLoginWithPassword(...);

const loginToken = await this.loginTokenService.generateLoginToken(
  user.email,
  workspace.id,
  AuthProviderEnum.Google      // ← Track which provider
);

return { loginToken };
```

---

### Flow 2: Google APIs OAuth (for Gmail/Calendar Access)

#### Purpose

Get **broad permissions** to access Gmail API and Google Calendar API to:
- Fetch all past emails/messages
- Fetch calendar events
- Send emails
- Monitor for new messages

#### Step-by-Step Process

```
1. USER CLICKS "CONNECT GMAIL" IN SETTINGS
   │
   ├─ Frontend makes: POST /auth/google-apis/request-code
   │  with transientToken (temporary auth token)
   │
   └─ Backend initiates OAuth with BROAD scopes

2. GOOGLE OAUTH CONSENT PAGE (BROAD SCOPE)
   │
   ├─ User sees: "Twenty CRM wants access to:"
   │  • Send emails on your behalf
   │  • Read your emails
   │  • Access your calendar
   │  • View your contacts
   │  [etc - much broader than login]
   │
   ├─ User clicks: "Allow"
   │
   └─ Browser redirected with authorization code

3. CALLBACK WITH AUTHORIZATION CODE
   │
   ├─ URL: GET /auth/google-apis/get-access-token?code=AUTH_CODE&state=STATE
   │
   ├─ Passport exchanges code for tokens
   │  (same process but with DIFFERENT scopes)
   │
   ├─ Google responds with:
   │  {
   │    access_token: '...',      ← For Gmail/Calendar API calls
   │    expires_in: 3600,
   │    refresh_token: '...',     ← Long-lived, save to DB
   │    token_type: 'Bearer',
   │    scope: 'https://www.googleapis.com/auth/gmail.send ...'
   │  }
   │
   └─ Different from login - these tokens have API permissions

4. EXTRACT USER INFO & TOKENS
   │
   ├─ GoogleAPIsOauthExchangeCodeForTokenStrategy.validate()
   │
   ├─ Extracts:
   │  {
   │    emails: [{value: 'gmail@gmail.com'}],
   │    accessToken: '...',      ← THE KEY: Will use for APIs
   │    refreshToken: '...',     ← Save for later refresh
   │    firstName: ...,
   │    lastName: ...,
   │    picture: ...,
   │    transientToken: '...'    ← Temp token to verify user
   │  }
   │
   └─ Calls done(null, user)

5. STORE IN DATABASE
   │
   ├─ Backend validates transientToken
   │  (proves user is authenticated)
   │
   ├─ Gets: workspaceMemberId, userId, workspaceId
   │
   ├─ Creates ConnectedAccount entity:
   │  {
   │    provider: 'google',
   │    email: 'gmail@gmail.com',
   │    accessToken: '...',        ← Encrypted and stored
   │    refreshToken: '...',       ← Encrypted and stored
   │    expiresAt: ...,
   │    workspaceMemberId: ...,
   │    userId: ...
   │  }
   │
   ├─ Creates MessageChannel:
   │  {
   │    connectedAccountId: ...,
   │    syncStatus: 'PENDING',
   │    syncStage: 'INITIAL'
   │  }
   │
   ├─ Creates CalendarChannel:
   │  {
   │    connectedAccountId: ...,
   │    syncStatus: 'PENDING',
   │    syncStage: 'INITIAL'
   │  }
   │
   └─ Enqueues background jobs to sync

6. BACKGROUND JOBS START SYNCING
   │
   ├─ MessagingMessageListFetchJob:
   │  • Uses accessToken to call Gmail API
   │  • Fetches all messages: GET /gmail/v1/users/me/messages
   │  • Stores in database
   │
   ├─ CalendarEventListFetchJob:
   │  • Uses accessToken to call Calendar API
   │  • Fetches events: GET /calendar/v3/calendars/primary/events
   │  • Stores in database
   │
   └─ Continues monitoring for new items

7. TOKEN REFRESH WHEN EXPIRED
   │
   ├─ When accessToken expires (expires_in: 3600)
   │
   ├─ Backend calls GoogleAPIRefreshAccessTokenService
   │  (from packages/twenty-server/src/modules/connected-account/refresh-tokens-manager/drivers/google/services/google-api-refresh-tokens.service.ts)
   │
   ├─ Uses googleapis library to refresh:
   │  const oAuth2Client = new google.auth.OAuth2(
   │    CLIENT_ID,
   │    CLIENT_SECRET
   │  );
   │  oAuth2Client.setCredentials({ refresh_token });
   │  const { token } = await oAuth2Client.getAccessToken();
   │
   ├─ Google returns new accessToken
   │
   ├─ Updates in database
   │
   └─ Continues syncing
```

#### Code Example: Google APIs Strategy

**File:** `packages/twenty-server/src/engine/core-modules/auth/strategies/google-apis-oauth-exchange-code-for-token.auth.strategy.ts`

```typescript
@Injectable()
export class GoogleAPIsOauthExchangeCodeForTokenStrategy
  extends GoogleAPIsOauthCommonStrategy {

  constructor(twentyConfigService: TwentyConfigService) {
    super(twentyConfigService);
    // Inherits config with BROAD scopes:
    // - https://www.googleapis.com/auth/gmail.send
    // - https://www.googleapis.com/auth/gmail.readonly
    // - https://www.googleapis.com/auth/calendar.readonly
    // - etc.
  }

  async validate(
    request: GoogleAPIsRequest,
    accessToken: string,       // ← THE KEY TOKEN
    refreshToken: string,      // ← Store for refresh
    profile: any,
    done: VerifyCallback,
  ): Promise<void> {
    const { name, emails, photos } = profile;
    const state = JSON.parse(request.query.state);

    const user: GoogleAPIsRequest['user'] = {
      emails,
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos?.[0]?.value,
      accessToken,             // ← Will use for Gmail API
      refreshToken,            // ← Will use for token refresh
      transientToken: state.transientToken,
      redirectLocation: state.redirectLocation,
      calendarVisibility: state.calendarVisibility,
      messageVisibility: state.messageVisibility,
      skipMessageChannelConfiguration:
        state.skipMessageChannelConfiguration,
    };

    done(null, user);
  }
}
```

#### Backend Processing

**File:** `packages/twenty-server/src/engine/core-modules/auth/controllers/google-apis-auth.controller.ts`

```typescript
@Get('get-access-token')
@UseGuards(
  GoogleAPIsOauthExchangeCodeForTokenGuard,
  PublicEndpointGuard,
  NoPermissionGuard,
)
async googleAuthGetAccessToken(
  @Req() req: GoogleAPIsRequest,
  @Res() res: Response,
) {
  const { user } = req;
  const {
    emails,
    accessToken,      // ← From OAuth provider
    refreshToken,     // ← From OAuth provider
    transientToken,
    redirectLocation,
    calendarVisibility,
    messageVisibility,
    skipMessageChannelConfiguration,
  } = user;

  // Get user info from transientToken
  const { workspaceMemberId, userId, workspaceId } =
    await this.transientTokenService.verifyTransientToken(transientToken);

  // Save Google API tokens to database
  await this.googleAPIsService.refreshGoogleRefreshToken({
    handle: emails[0].value,  // Gmail address
    workspaceMemberId,
    workspaceId,
    accessToken,
    refreshToken,
    calendarVisibility,
    messageVisibility,
    skipMessageChannelConfiguration,
  });

  // Redirect user to success page
  res.redirect(redirectLocation);
}
```

#### Using Tokens to Sync

**File:** `packages/twenty-server/src/engine/core-modules/auth/services/google-apis.service.ts`

```typescript
async refreshGoogleRefreshToken(input: {
  handle: string;
  workspaceMemberId: string;
  workspaceId: string;
  accessToken: string;
  refreshToken: string;
  calendarVisibility: CalendarChannelVisibility | undefined;
  messageVisibility: MessageChannelVisibility | undefined;
  skipMessageChannelConfiguration?: boolean;
}): Promise<string> {
  // 1. Create/update ConnectedAccount
  const connectedAccount = await this.createConnectedAccountService.saveAccount(
    handle,
    input.accessToken,
    input.refreshToken,
    ConnectedAccountProvider.GOOGLE,
    input.workspaceMemberId,
  );

  // 2. Create MessageChannel to sync emails
  if (!input.skipMessageChannelConfiguration) {
    await this.createMessageChannelService.createMessageChannel(
      handle,
      ConnectedAccountProvider.GOOGLE,
      input.messageVisibility,
      input.workspaceMemberId,
      input.workspaceId,
      connectedAccount.id,
    );
  }

  // 3. Create CalendarChannel to sync calendar events
  if (input.calendarVisibility) {
    await this.createCalendarChannelService.createCalendarChannel(
      handle,
      ConnectedAccountProvider.GOOGLE,
      input.calendarVisibility,
      input.workspaceMemberId,
      input.workspaceId,
      connectedAccount.id,
    );
  }

  // 4. Queue background jobs to fetch messages and events
  await this.messageQueueService.add(
    MessagingMessageListFetchJob,
    {
      connectedAccountId: connectedAccount.id,
      workspaceId: input.workspaceId,
    }
  );

  await this.calendarQueueService.add(
    CalendarEventListFetchJob,
    {
      connectedAccountId: connectedAccount.id,
      workspaceId: input.workspaceId,
    }
  );

  return connectedAccount.id;
}
```

---

## Microsoft OAuth Flow in Twenty

### Overview

Similar to Google, but uses Microsoft/Azure OAuth and Microsoft Graph API.

Two strategies:
1. **MicrosoftStrategy** - For login (scopes: user.read)
2. **MicrosoftAPIsOauthCommonStrategy** - For API access (scopes: Mail.Send, Calendar.Read)

### Microsoft OAuth Endpoints

```
Authorization endpoint:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize

Token endpoint:
https://login.microsoftonline.com/common/oauth2/v2.0/token

Tenant: 'common' (allow personal + work accounts)
```

### Flow 1: Microsoft Login OAuth

Similar to Google login, but optimized for Microsoft accounts:

```
User clicks "Sign in with Microsoft"
         ↓
Passport redirects to Azure AD OAuth
         ↓
User sees consent screen (scopes: user.read)
         ↓
Azure AD redirects back with auth code
         ↓
Passport exchanges code for user profile
         ↓
Backend creates/logins user
         ↓
Generates JWT LoginToken (authProvider: 'microsoft')
```

**File:** `packages/twenty-server/src/engine/core-modules/auth/strategies/microsoft.auth.strategy.ts`

```typescript
export class MicrosoftStrategy extends PassportStrategy(Strategy, 'microsoft') {
  constructor(twentyConfigService: TwentyConfigService) {
    super({
      clientID: twentyConfigService.get('AUTH_MICROSOFT_CLIENT_ID'),
      clientSecret: twentyConfigService.get('AUTH_MICROSOFT_CLIENT_SECRET'),
      callbackURL: twentyConfigService.get('AUTH_MICROSOFT_CALLBACK_URL'),
      tenant: 'common',  // Allow personal + work accounts
      scope: ['user.read'],  // ← MINIMAL for login
      passReqToCallback: true,
    });
  }

  async validate(
    request: MicrosoftRequest,
    _accessToken: string,
    _refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<void> {
    const { name, userPrincipalName, photos } = profile;
    const state = JSON.parse(request.query.state);

    if (!userPrincipalName) {
      throw new AuthException(
        'User principal name not found',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    const user: MicrosoftRequest['user'] = {
      email: userPrincipalName,  // Outlook email
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos?.[0]?.value,
      workspaceInviteHash: state.workspaceInviteHash,
      workspacePersonalInviteToken: state.workspacePersonalInviteToken,
      workspaceId: state.workspaceId,
      billingCheckoutSessionState: state.billingCheckoutSessionState,
      locale: state.locale,
      action: state.action,
    };

    done(null, user);
  }
}
```

### Flow 2: Microsoft APIs OAuth (for Outlook/Calendar Access)

Get **broad permissions** to access Microsoft Graph API:

```
User clicks "Connect Outlook" in settings
         ↓
Passport redirects to Azure AD with BROAD scopes
         ↓
Scopes:
  • offline_access (get refresh token)
  • User.Read (read profile)
  • Mail.Send (send emails)
  • Mail.Read (read emails)
  • Calendars.Read (read calendar)
  • Calendars.ReadWrite (optional)
         ↓
User sees consent screen (can take longer for Outlook)
         ↓
Azure AD redirects back with auth code
         ↓
Passport exchanges code for tokens (accessToken + refreshToken)
         ↓
Backend stores in ConnectedAccount
         ↓
Queues background jobs to sync via Microsoft Graph API
```

**File:** `packages/twenty-server/src/engine/core-modules/auth/strategies/microsoft-apis-oauth-common.auth.strategy.ts`

```typescript
export abstract class MicrosoftAPIsOauthCommonStrategy
  extends PassportStrategy(Strategy, 'microsoft-apis') {

  constructor(twentyConfigService: TwentyConfigService) {
    const scopes = getMicrosoftApisOauthScopes();  // BROAD scopes

    super({
      clientID: twentyConfigService.get('AUTH_MICROSOFT_CLIENT_ID'),
      clientSecret: twentyConfigService.get('AUTH_MICROSOFT_CLIENT_SECRET'),
      tenant: 'common',
      callbackURL: twentyConfigService.get('AUTH_MICROSOFT_APIS_CALLBACK_URL'),
      scope: scopes,  // Broad permissions
      passReqToCallback: true,
    });
  }

  abstract validate(
    request: Express.Request,
    accessToken: string,
    refreshToken: string,
    profile: unknown,
    done: VerifyCallback,
  ): Promise<void>;
}
```

**File:** `packages/twenty-server/src/engine/core-modules/auth/strategies/microsoft-apis-oauth-exchange-code-for-token.auth.strategy.ts`

```typescript
@Injectable()
export class MicrosoftAPIsOauthExchangeCodeForTokenStrategy
  extends MicrosoftAPIsOauthCommonStrategy {

  constructor(twentyConfigService: TwentyConfigService) {
    super(twentyConfigService);
  }

  async validate(
    request: MicrosoftAPIsRequest,
    accessToken: string,      // ← For Microsoft Graph API calls
    refreshToken: string,     // ← For token refresh
    profile: any,
    done: VerifyCallback,
  ): Promise<void> {
    const { name, emails, photos } = profile;
    const state = JSON.parse(request.query.state);

    const user: MicrosoftAPIsRequest['user'] = {
      emails,
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos?.[0]?.value,
      accessToken,           // ← To call Microsoft Graph
      refreshToken,          // ← To refresh tokens
      transientToken: state.transientToken,
      redirectLocation: state.redirectLocation,
      calendarVisibility: state.calendarVisibility,
      messageVisibility: state.messageVisibility,
    };

    done(null, user);
  }
}
```

### Using Microsoft Graph API

After tokens are stored, background jobs use them:

```typescript
// Example: Fetch emails from Outlook
GET https://graph.microsoft.com/v1.0/me/messages
Authorization: Bearer {accessToken}

// Example: Fetch calendar events
GET https://graph.microsoft.com/v1.0/me/calendar/events
Authorization: Bearer {accessToken}

// Example: Send email
POST https://graph.microsoft.com/v1.0/me/sendMail
Authorization: Bearer {accessToken}
Content-Type: application/json
{
  "message": {
    "subject": "...",
    "body": {...},
    "toRecipients": [...]
  }
}
```

---

## Comparison with Email POC

### 1. OAuth Flow Architecture

#### Email POC

```
┌─────────────────────────┐
│   Single OAuth Flow      │
│                          │
│  Scopes:                 │
│  • Gmail: gmail.send     │
│  • Outlook: Mail.Send    │
│                          │
│  Purpose:                │
│  - Get permission to     │
│    SEND emails only      │
│                          │
│  Result:                 │
│  - Store tokens          │
│  - Use to send email     │
└─────────────────────────┘
```

#### Twenty CRM

```
┌────────────────────────────────────────┐
│   Dual OAuth Flows                     │
│                                        │
│  Flow 1: Login OAuth (MINIMAL scopes)  │
│  ├─ Google: email, profile             │
│  ├─ Microsoft: user.read               │
│  └─ Purpose: Authenticate into Twenty  │
│                                        │
│  Flow 2: APIs OAuth (BROAD scopes)     │
│  ├─ Google: gmail.send, calendar, etc. │
│  ├─ Microsoft: Mail.Send, Calendar...  │
│  └─ Purpose: Sync entire inbox/cal.    │
└────────────────────────────────────────┘
```

**Difference:** Email POC focuses on one action (send email). Twenty CRM separates user authentication from deep service integration.

---

### 2. Scope Comparison

#### Email POC Scopes

```
Google:
  https://www.googleapis.com/auth/gmail.send
  - Permission: Send emails ONLY
  - Cannot: Read emails, access calendar

Microsoft:
  offline_access User.Read Mail.Send
  - Permission: Read profile, send emails
  - Cannot: Read existing emails, access calendar
```

#### Twenty CRM Scopes

**Login OAuth:**
```
Google:
  email, profile
  - Permission: Get email + profile
  - Use: Authenticate user

Microsoft:
  user.read
  - Permission: Get profile
  - Use: Authenticate user
```

**APIs OAuth:**
```
Google:
  https://www.googleapis.com/auth/gmail.send
  https://www.googleapis.com/auth/gmail.readonly
  https://www.googleapis.com/auth/calendar.readonly
  https://www.googleapis.com/auth/contacts.readonly
  - Permission: Send, read emails, read calendar/contacts
  - Use: Sync past emails and calendar events

Microsoft:
  offline_access
  User.Read
  Mail.Send
  Mail.Read
  Calendars.Read
  - Permission: Everything above + renew tokens without user
  - Use: Sync past emails and calendar events
```

**Difference:** Email POC minimal scopes for one action. Twenty broader scopes to sync entire communication history.

---

### 3. Token Storage

#### Email POC

```
PostgreSQL: oauth_connections table
├── org_name (TEXT) - Organization
├── provider (TEXT) - 'google' or 'microsoft'
├── access_token (TEXT) - Current API token
├── refresh_token (TEXT) - Long-lived refresh token
├── expires_at (BIGINT) - When access token expires
├── token_type (TEXT) - "Bearer"
├── scope (TEXT) - Permissions granted
├── last_login_at (BIGINT) - Last auth
├── last_refresh_at (BIGINT) - Last refresh
└── updated_at (BIGINT)

Document-oriented: All fields in one row
```

#### Twenty CRM

```
Multiple Entities:

1. ConnectedAccount (OAuth tokens for APIs)
   ├── provider: 'google' | 'microsoft'
   ├── accessToken (encrypted)
   ├── refreshToken (encrypted)
   ├── expiresAt
   ├── workspaceMemberId
   └── userId

2. MessageChannel (For email syncing)
   ├── connectedAccountId
   ├── syncStatus: 'INITIAL' | 'ACTIVE' | 'PARTIAL' | 'STOPPED'
   ├── syncStage: ...
   └── ...

3. CalendarChannel (For calendar syncing)
   ├── connectedAccountId
   ├── syncStatus
   └── ...

Object-relational: Tokens separated from sync metadata
```

**Difference:** Email POC stores everything flat. Twenty separates concerns into specialized entities.

---

### 4. Token Refresh Strategy

#### Email POC

```
Timeline for token refresh:

Token issued: T=0
├── expires_at = now + 3600 (1 hour)
│
├── T=0 to T=3540
│   └─ Token is valid, ignore
│
├── T=3540 (60 seconds before expiry)
│   └─ DEV_APP checks: now + 60 >= expires_at?
│       └─ YES: Refresh token
│
├── On refresh:
│   ├─ Check refresh_token exists
│   ├─ POST to provider: exchange refresh_token for new access_token
│   ├─ Save new access_token
│   ├─ Update expires_at
│   ├─ Update last_refresh_at
│   └─ Continue operations
│
└─ If refresh fails: Throw "Token Expired" error
   └─ User must re-authenticate

Manual check:
- Only happens when user sends an email
- If token expired, error thrown to user
```

#### Twenty CRM

```
Timeline (same concept but automated):

Token issued: T=0
├── expires_at = now + 3600 (1 hour)
│
├── Background jobs running continuously
│
├─ Every job checks: Is token expired or about to expire?
│   ├─ YES: Automatically refresh before use
│   ├─ Call GoogleAPIRefreshAccessTokenService
│   ├─ Save new token to DB
│   └─ Continue syncing silently
│
├─ If token invalid (refresh token expired):
│   ├─ Pause syncing
│   ├─ Wait for user to reconnect account
│   └─ Update UI with "Reconnect needed"
│
└─ User experience: Seamless, no interruption

Automatic & continuous:
- Happens before every API call
- Happens in background jobs
- User never sees token errors
- Proactive, not reactive
```

**Difference:** Email POC requires user to handle token expiry. Twenty CRM handles automatically.

---

### 5. CSRF Protection (State Token)

#### Email POC

```
State Token Process:

1. OAuth Initiation:
   ├─ Generate: state = secrets.token_urlsafe(32)
   │  (cryptographically secure random, 32 bytes = 256 bits)
   │
   ├─ Save to DB: (org_name, provider, state, state_created_at)
   │
   └─ Redirect: https://oauth-provider.com/auth?state=ABC123...

2. Callback:
   ├─ Receive: state=ABC123...
   │
   ├─ Lookup in DB: SELECT * FROM oauth_connections
   │                WHERE org = org_name AND state = ABC123
   │
   ├─ Validate:
   │  • State matches exactly
   │  • state_created_at < 600 seconds (10 minutes) ago
   │  (prevents old/replayed tokens)
   │
   ├─ If valid:
   │  • Clear state from DB
   │  • Use org_name from DB (not from query param)
   │  • Get access token
   │
   └─ If invalid: Reject callback, log as potential CSRF
```

#### Twenty CRM

```
State Token Process (similar but with complex data):

1. OAuth Initiation:
   ├─ Passport auto-generates state
   │
   ├─ Serialize state as JSON:
   │  {
   │    transientToken: temp_auth_token,
   │    workspaceId: workspace_123,
   │    redirectLocation: /settings/...,
   │    calendarVisibility: 'metadata',
   │    messageVisibility: 'sharing',
   │    skipMessageChannelConfiguration: false
   │  }
   │
   └─ Pass as state parameter

2. Callback:
   ├─ Receive: state=JSON_data
   │
   ├─ Passport validates state automatically
   │
   ├─ Deserialize state JSON
   │
   ├─ Verify transientToken:
   │  • Must be valid JWT
   │  • Must decode to workspaceId, userId, etc.
   │  • Must not be expired
   │
   ├─ If valid:
   │  • Extract metadata from state
   │  • Use to set up message/calendar channels
   │  • Redirect to stored location
   │
   └─ If invalid: Reject
```

**Difference:** Both protect against CSRF. Email POC uses DB with timestamp check. Twenty uses JWT in state.

---

### 6. Error Handling

#### Email POC

```
Logging (json_log.py):

1. OAuth Events:
   ├─ oauth_consent_generated
   ├─ oauth_callback_received
   ├─ oauth_error
   ├─ oauth_state_invalid
   └─ oauth_token_error

2. Token Events:
   ├─ token_refresh_start
   ├─ token_refresh_failed
   ├─ token_expired_no_refresh
   └─ token_missing

3. Email Events:
   ├─ email_send_request
   ├─ email_send_success (with latency)
   └─ email_send_failed

Never logs:
- Full access tokens (only metadata)
- User passwords
- Full error stacks
```

#### Twenty CRM

```
Exception Handling (NestJS):

1. Exception Class:
   AuthException
   ├─ message: string
   ├─ code: AuthExceptionCode
   └─ userFriendlyMessage: MessageDescriptor

2. Auth Exception Codes:
   ├─ GOOGLE_API_AUTH_DISABLED
   ├─ MICROSOFT_API_AUTH_DISABLED
   ├─ INVALID_JWT_TOKEN_TYPE
   ├─ EMAIL_NOT_VERIFIED
   ├─ INSUFFICIENT_SCOPES
   ├─ OAUTH_ACCESS_DENIED
   ├─ SSO_AUTH_FAILED
   └─ ... many more

3. Exception Filters:
   ├─ AuthGraphqlApiExceptionFilter
   ├─ CaptchaGraphqlApiExceptionFilter
   ├─ EmailVerificationExceptionFilter
   ├─ TwoFactorAuthenticationExceptionFilter
   └─ PermissionsGraphqlApiExceptionFilter

4. Response:
   - Transforms to GraphQL error format
   - Sends user-friendly message to frontend
   - Logs structured error data
   - Never exposes sensitive info
```

**Difference:** Email POC uses centralized logging file. Twenty uses NestJS exception infrastructure.

---

### 7. Multi-Tenancy

#### Email POC

```
Organization-Level Isolation:

Per request header: x-org-name
├─ Example: x-org-name: acme_corp

Database lookups:
├─ oauth_connections WHERE org_name = 'acme_corp' AND provider = 'google'

Result:
├─ acme_corp.google (tokens)
├─ acme_corp.microsoft (tokens)
└─ Other orgs cannot access these tokens

Zero user-level distinction within org:
- All tokens for org shared (or default to one account)
```

#### Twenty CRM

```
Workspace + User Level Isolation:

Hierarchical:
├─ Workspace (top level)
│  ├─ User 1
│  │  ├─ Google tokens (ConnectedAccount)
│  │  ├─ Microsoft tokens (ConnectedAccount)
│  │  └─ MessageChannel + CalendarChannel
│  │
│  └─ User 2
│     ├─ Different Google tokens
│     ├─ Different Microsoft tokens
│     └─ Different channels
│
└─ Workspace 2 (separate tenant)
   └─ Completely isolated

Result:
- Each user has own OAuth tokens
- Multiple users can connect different accounts
- Tokens are user-specific, not org-wide
```

**Difference:** Email POC org-level. Twenty user-level with workspace scoping.

---

### 8. Use Cases

#### Email POC

```
Use Case: Send Email from Another Account

Flow:
1. User logs in to Email POC
2. User clicks "Connect Gmail"
3. User approves Gmail.send scope
4. Tokens stored
5. User enters recipient + body
6. Clicks "Send"
7. Backend uses tokens to call: POST gmail.send API
8. Email sent
9. Done

Action: SYNCHRONOUS, ON-DEMAND
Scope: MINIMAL (send only)
Continuity: ONE-TIME per send
```

#### Twenty CRM

```
Use Case: Integrate Email + Calendar into CRM

Flow:
1. User logs in to Twenty
2. User goes to settings
3. User clicks "Connect Gmail"
4. User approves broad scopes (send, read, calendar)
5. Tokens stored
6. Backend queues: CalendarEventListFetchJob
7. Backend queues: MessagingMessageListFetchJob
8. Jobs run continuously:
   ├─ Fetch ALL past emails
   ├─ Store in database
   ├─ Fetch ALL calendar events
   ├─ Store in database
   ├─ Monitor for new items
   ├─ Update in real-time
   └─ Refresh tokens automatically
9. User sees emails + calendar in CRM UI
10. Continuous (days/months)

Action: ASYNCHRONOUS, CONTINUOUS
Scope: BROAD (full integration)
Continuity: ONGOING background jobs
```

**Difference:** Email POC is transaction-based (each email send). Twenty is integration-based (continuous sync).

---

### 9. Performance & Scalability

#### Email POC

```
Synchronous approach:
├─ User clicks "Send"
├─ Request goes to backend
├─ Backend blocks:
│  ├─ Check token
│  ├─ Call Gmail API
│  ├─ Wait for response (network latency)
│  └─ Return to user
├─ Response time: 1-5 seconds
└─ User waits

Scaling:
├─ Limited to API rate limits (Gmail: ~1000/sec per user)
├─ Each request blocks one server thread
├─ Cannot benefit from batch operations
```

#### Twenty CRM

```
Asynchronous approach:
├─ User clicks "Connect Gmail"
├─ Returns immediately
├─ Background jobs queue up:
│  ├─ CalendarEventListFetchJob
│  ├─ MessagingMessageListFetchJob
│  └─ Monitoring jobs
├─ Jobs run on separate process (BullMQ)
├─ Doesn't block user
├─ Can batch API calls
└─ More efficient

Scaling:
├─ Uses message queue (BullMQ)
├─ Can have multiple workers
├─ Can retry on failure
├─ Can batch requests
├─ Doesn't block main API threads
├─ Much more scalable
```

**Difference:** Email POC synchronous/blocking. Twenty asynchronous/non-blocking.

---

### 10. Summary Table

| Feature | Email POC | Twenty CRM |
|---------|-----------|-----------|
| **OAuth Flows** | 1 (login + send) | 2 (login separate from APIs) |
| **Scopes** | Minimal (send only) | Broad (full integration) |
| **Database Schema** | Flat table | Relational entities |
| **Token Refresh** | Manual on-demand | Automatic background |
| **Refresh Strategy** | On error | Proactive (60sec before expiry) |
| **State Token** | DB + timestamp | JWT in state parameter |
| **Error Handling** | JSON logging file | NestJS exception filters |
| **Multi-tenancy** | Organization-level | User + Workspace level |
| **Use Case** | Send one email | Integrate full communication |
| **Architecture** | Synchronous/blocking | Asynchronous/background jobs |
| **API Calls** | Per-request when user acts | Continuous background syncing |
| **User Experience** | User initiates action | Silent, always up-to-date |
| **Scalability** | Limited | High (message queue) |
| **Complexity** | Simple, focused | Complex, enterprise |
| **Framework** | FastAPI (Python) | NestJS (TypeScript) |

---

## Security Considerations

### Both Email POC and Twenty CRM

#### ✅ Implemented

1. **State Token / CSRF Protection**
   - Both use state tokens
   - Validated on callback
   - Email POC: DB timestamp check
   - Twenty: JWT validation

2. **HTTPS Required**
   - OAuth exchanges only via HTTPS
   - Tokens never in URL (always POST body)
   - Callback URLs must be HTTPS

3. **No Password Storage**
   - OAuth tokens ≠ passwords
   - Passwords never sent to Google/Microsoft
   - Both use standard OAuth, not proprietary auth

4. **Token Encryption**
   - Email POC: Tokens encrypted at rest in DB
   - Twenty: Tokens encrypted via AES-256-CTR

5. **Scope Limitation**
   - Email POC: Just gmail.send, Mail.Send
   - Twenty: Scopes clearly defined in code

#### ⚠️ Best Practices

1. **Environment Variables**
   - Client ID, Client Secret → env vars only
   - Never hardcoded
   - Never in version control

2. **Token Rotation**
   - Both support refresh tokens
   - Access tokens short-lived (15-60 min)
   - Refresh tokens long-lived (90 days to 1 year)

3. **Error Messages**
   - Don't expose full token values
   - Don't expose internals in error messages
   - One message per error type

4. **Logging**
   - Log event (oauth_callback_received)
   - Never log tokens
   - Log only metadata (user_id, timestamp)

---

## Token Management

### Access Token Lifecycle

```
GOOGLE:
Issue:
├─ scope: gmail.send, calendar
├─ expires_in: 3600 (1 hour)
├─ token_type: Bearer
└─ Can call: /gmail/v1/users/me/messages

MICROSOFT:
Issue:
├─ scope: Mail.Send, Calendars.Read
├─ expires_in: 3600 (1 hour)
├─ token_type: Bearer
└─ Can call: /graph.microsoft.com/v1.0/me/messages

After 3600 seconds:
├─ Token is invalid
├─ API calls fail with 401 Unauthorized
├─ Must refresh with refresh_token

Email POC:
├─ On 401: Refresh immediately
├─ User sees: "Reconnect needed"

Twenty:
├─ On 401: Pause sync
├─ Automatic retry with new token
├─ User doesn't see error (silent failure)
```

### Refresh Token Lifecycle

```
GOOGLE:
├─ Issued: During OAuth consent
├─ Expiry: Never (actually ~6 months if unused)
├─ Use: POST /token with grant_type=refresh_token
├─ Returns: New access_token (+ new expires_in)
│
└─ Important: Google returns refresh_token ONLY on first consent
    (If user reconnects, don't get new refresh_token)
    (Must reuse old one or handle gracefully)

MICROSOFT:
├─ Issued: During OAuth consent
├─ Expiry: ~90 days
├─ Use: POST /token with grant_type=refresh_token
├─ Returns: New access_token + new refresh_token
│
└─ Microsoft refreshes the refresh_token too
    (Every refresh gives new refresh_token)
    (Older ones become invalid)

Email POC:
├─ Saves refresh_token to DB
├─ Updates last_refresh_at
├─ Reuses refresh_token if provider doesn't return new one
└─ Handles Google's one-refresh-token limitation

Twenty:
├─ Uses googleapis library (handles details)
├─ Automatically manages refresh tokens
├─ Updates expiry times
└─ Highly abstracted from provider details
```

---

## Conclusion

### Email POC: Simple, Focused
- ✅ Minimal OAuth scopes
- ✅ Simple database schema
- ✅ Straightforward state management
- ✅ Good for: Sending emails from external accounts
- ❌ Not suitable for: Complex integrations

### Twenty CRM: Enterprise, Complete
- ✅ Sophisticated OAuth architecture
- ✅ All security best practices
- ✅ Automatic token management
- ✅ Background job infrastructure
- ✅ Multi-user, multi-workspace scoping
- ✅ Good for: Full email/calendar CRM integration
- ❌ Overkill for: Simple operations

Both correctly implement OAuth 2.0, but solve different problems. Email POC is deliberately simple. Twenty CRM is deliberately comprehensive.
