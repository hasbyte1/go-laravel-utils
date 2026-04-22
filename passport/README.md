# passport

Package `passport` provides an OAuth2/OIDC authorization server for Go,
modelled after [Laravel Passport](https://laravel.com/docs/passport). It wraps
[ory/fosite](https://github.com/ory/fosite) internally — fosite never leaks
into the public API.

```
go get github.com/hasbyte1/go-laravel-utils/passport
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [Architecture](#architecture)
3. [Grant types](#grant-types)
   - [Authorization Code + PKCE](#authorization-code--pkce)
   - [Client Credentials](#client-credentials)
   - [Refresh Token](#refresh-token)
   - [Device Authorization (partial)](#device-authorization-partial)
4. [Storage interfaces](#storage-interfaces)
   - [ClientStore](#clientstore)
   - [AuthorizationCodeStore](#authorizationcodestore)
   - [AccessTokenStore](#accesstokenstore)
   - [RefreshTokenStore](#refreshtokenstore)
   - [DeviceStore](#devicestore)
   - [Example SQL schema](#example-sql-schema)
5. [Behaviour interfaces](#behaviour-interfaces)
   - [UserSessionProvider](#usersessionprovider)
   - [ConsentProvider](#consentprovider)
   - [UserInfoProvider](#userinfoprovider)
6. [HTTP routes](#http-routes)
7. [ResourceGuard](#resourceguard)
   - [Static key](#static-key)
   - [Remote JWKS](#remote-jwks)
   - [Middleware](#middleware)
   - [Manual validation](#manual-validation)
8. [OAuthClient reference](#oauthclient-reference)
9. [Config reference](#config-reference)
10. [Error reference](#error-reference)
11. [Laravel comparison](#laravel-comparison)

---

## Quick start

```go
import (
    "crypto/rand"
    "crypto/rsa"
    "net/http"

    "github.com/hasbyte1/go-laravel-utils/passport"
    "github.com/hasbyte1/go-laravel-utils/passport/inmemory"
)

// 1. Generate (or load from disk) an RSA signing key.
key, _ := rsa.GenerateKey(rand.Reader, 2048)

// 2. Create stores (replace inmemory with your DB implementation).
store := inmemory.New()
store.AddClient(&passport.OAuthClient{
    ID:           "my-spa",
    Name:         "My SPA",
    RedirectURIs: []string{"https://app.example.com/callback"},
    GrantTypes:   []string{"authorization_code", "refresh_token"},
    Scopes:       []string{"openid", "profile", "email"},
    Public:       true, // PKCE required
})

// 3. Configure.
secret := make([]byte, 32)
rand.Read(secret)

cfg := passport.DefaultConfig("https://auth.example.com")
cfg.GlobalSecret = secret
cfg.LoginURL    = "https://auth.example.com/login"
cfg.ConsentURL  = "https://auth.example.com/consent"

// 4. Build the server.
srv, err := passport.NewServer(
    cfg,
    store,   // ClientStore
    store,   // AuthorizationCodeStore
    store,   // AccessTokenStore
    store,   // RefreshTokenStore
    store,   // DeviceStore
    mySessionProvider,  // UserSessionProvider
    myConsentProvider,  // ConsentProvider
    myUserInfoProvider, // UserInfoProvider
    myUserProvider,     // sanctum.UserProvider (for /userinfo lookup)
    key,
)

// 5. Mount routes.
mux := http.NewServeMux()
srv.RegisterRoutes(mux)
http.ListenAndServe(":8080", mux)
```

---

## Architecture

```
                     Browser / Client
                           │
          ┌────────────────▼────────────────┐
          │         passport.Server          │
          │                                  │
          │  GET  /oauth/authorize           │
          │  POST /oauth/token               │
          │  POST /oauth/revoke              │
          │       /oauth/userinfo            │
          │  GET  /.well-known/openid-config │
          │  GET  /.well-known/jwks.json     │
          └──┬────────────┬─────────────────┘
             │            │
    ┌────────▼──┐   ┌─────▼──────────────┐
    │  fosite   │   │  consumer stores   │
    │ (internal)│   │  & providers       │
    └───────────┘   │                    │
                    │  ClientStore       │
                    │  AuthCodeStore     │
                    │  AccessTokenStore  │
                    │  RefreshTokenStore │
                    │  DeviceStore       │
                    │                    │
                    │  UserSession-      │
                    │    Provider        │
                    │  ConsentProvider   │
                    │  UserInfoProvider  │
                    └────────────────────┘

        API service (separate process)
                    │
          ┌─────────▼──────────┐
          │  ResourceGuard     │  validates JWT access tokens
          │  (static key OR    │  without database access
          │   remote JWKS)     │
          └────────────────────┘
```

The `passport.Server` is your authorization server. Downstream API services use
`passport.ResourceGuard` to validate the JWT access tokens the server issues —
they do not need access to the database.

---

## Grant types

### Authorization Code + PKCE

Designed for user-facing applications (SPAs, mobile apps, server-side web apps).
S256 PKCE is enforced for all public clients; the `plain` method is disabled.

**Step 1 — redirect the user to the authorize endpoint:**

```
GET /oauth/authorize
    ?response_type=code
    &client_id=my-spa
    &redirect_uri=https://app.example.com/callback
    &scope=openid+profile
    &state=RANDOM_STATE
    &code_challenge=BASE64URL(SHA256(code_verifier))
    &code_challenge_method=S256
```

The server:
1. Calls `UserSessionProvider.GetUser` — redirects to `Config.LoginURL` when `nil`.
2. Calls `ConsentProvider.IsConsentGranted` — redirects to `Config.ConsentURL` when `false`.
3. Redirects back: `https://app.example.com/callback?code=CODE&state=RANDOM_STATE`.

**Step 2 — exchange the code for tokens:**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=CODE
&redirect_uri=https://app.example.com/callback
&client_id=my-spa
&code_verifier=ORIGINAL_VERIFIER
```

**Response:**

```json
{
  "access_token":  "<RS256 JWT>",
  "token_type":    "bearer",
  "expires_in":    3600,
  "refresh_token": "<opaque HMAC token>",
  "id_token":      "<RS256 JWT>"
}
```

### Client Credentials

For machine-to-machine API access with no user involved.

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic BASE64(client_id:client_secret)

grant_type=client_credentials&scope=read
```

Or via POST body:

```
grant_type=client_credentials
&client_id=my-service
&client_secret=SECRET
&scope=read
```

### Refresh Token

Exchange a refresh token for a new access token. The old refresh token is
rotated (invalidated) on each use.

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=my-spa
```

For confidential clients, include `client_secret` as well.

### Device Authorization (partial)

`DeviceStore`, `ApproveDevice`, and `DenyDevice` are fully implemented.
The HTTP endpoint (`POST /oauth/device/code`) returns `501 Not Implemented`
because fosite v0.49 does not ship `RFC8628DeviceAuthorizationGrantFactory`.
Upgrade fosite to a version with RFC 8628 support to activate it.

```go
// Call from your device verification page handler:
err := srv.ApproveDevice(ctx, userCode, loggedInUser)
err  = srv.DenyDevice(ctx, userCode)
```

---

## Storage interfaces

Implement these five interfaces against your own database. The passport server
calls them; your code provides the SQL / NoSQL / cache layer.

### ClientStore

```go
type ClientStore interface {
    GetClient(ctx context.Context, id string) (*OAuthClient, error)
    // Return ErrClientNotFound when the client does not exist.
}
```

### AuthorizationCodeStore

```go
type AuthorizationCodeStore interface {
    CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

    GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
    // Return ErrCodeNotFound when absent.
    // Return (record, ErrCodeInvalidated) when Active == false — the record
    // must still be returned so the server can revoke associated tokens.

    InvalidateAuthorizationCode(ctx context.Context, code string) error
    // Set Active = false. The record must remain retrievable as ErrCodeInvalidated.

    DeleteAuthorizationCode(ctx context.Context, code string) error
}
```

### AccessTokenStore

```go
type AccessTokenStore interface {
    CreateAccessToken(ctx context.Context, token *AccessToken) error

    GetAccessToken(ctx context.Context, signature string) (*AccessToken, error)
    // Return ErrTokenNotFound when absent.

    DeleteAccessToken(ctx context.Context, signature string) error

    DeleteAccessTokensBySubject(ctx context.Context, subject string) error
    // Caller-facing helper for logout / account-deletion flows.
    // The server itself never calls this method.

    DeleteAccessTokensByRequestID(ctx context.Context, requestID string) error
    // Called by the server during token revocation.
}
```

### RefreshTokenStore

```go
type RefreshTokenStore interface {
    CreateRefreshToken(ctx context.Context, token *RefreshToken) error

    GetRefreshToken(ctx context.Context, signature string) (*RefreshToken, error)
    // Return ErrTokenNotFound when absent.
    // Return (record, ErrTokenInactive) when Active == false — the record
    // must still be returned alongside the error.

    DeleteRefreshToken(ctx context.Context, signature string) error

    DeleteRefreshTokensBySubject(ctx context.Context, subject string) error
    // Caller-facing helper for logout / account-deletion flows.
    // The server itself never calls this method.

    RevokeRefreshTokensByRequestID(ctx context.Context, requestID string) error
    // Set Active = false for all tokens with the given request ID.
    // Called by the server during refresh token rotation.
}
```

### DeviceStore

```go
type DeviceStore interface {
    CreateDeviceCode(ctx context.Context, req *DeviceCode) error

    GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
    // Return ErrDeviceNotFound when absent.

    GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
    // Return ErrDeviceNotFound when absent.

    UpdateDeviceCode(ctx context.Context, req *DeviceCode) error
    // Used by ApproveDevice / DenyDevice to set Status and UserID.

    DeleteDeviceCode(ctx context.Context, deviceCode string) error
}
```

### Example SQL schema

```sql
CREATE TABLE oauth_clients (
    id            TEXT PRIMARY KEY,
    secret_hash   TEXT NOT NULL,         -- bcrypt hash of client secret
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,         -- JSON array, e.g. '["https://…"]'
    grant_types   TEXT NOT NULL,         -- JSON array
    scopes        TEXT NOT NULL,         -- JSON array
    public        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE oauth_authorization_codes (
    code          TEXT PRIMARY KEY,
    request_id    TEXT      NOT NULL,    -- used for token revocation on replay
    client_id     TEXT      NOT NULL,
    user_id       TEXT      NOT NULL,
    redirect_uri  TEXT,
    scopes        TEXT      NOT NULL,    -- JSON array
    expires_at    TIMESTAMP NOT NULL,
    active        BOOLEAN   NOT NULL DEFAULT TRUE,
    session_data  BLOB      NOT NULL,    -- opaque; store and return unchanged
    nonce         TEXT
);

CREATE TABLE oauth_access_tokens (
    signature     TEXT PRIMARY KEY,      -- JWT signature segment
    request_id    TEXT      NOT NULL,
    client_id     TEXT      NOT NULL,
    user_id       TEXT,                  -- empty for client_credentials
    scopes        TEXT      NOT NULL,
    expires_at    TIMESTAMP NOT NULL,
    session_data  BLOB      NOT NULL
);

CREATE TABLE oauth_refresh_tokens (
    signature     TEXT PRIMARY KEY,
    request_id    TEXT      NOT NULL,
    client_id     TEXT      NOT NULL,
    user_id       TEXT,
    scopes        TEXT      NOT NULL,
    expires_at    TIMESTAMP NOT NULL,
    active        BOOLEAN   NOT NULL DEFAULT TRUE,
    session_data  BLOB      NOT NULL
);

CREATE TABLE oauth_device_codes (
    device_code      TEXT PRIMARY KEY,
    user_code        TEXT      NOT NULL UNIQUE,
    request_id       TEXT      NOT NULL,
    client_id        TEXT      NOT NULL,
    scopes           TEXT      NOT NULL,
    expires_at       TIMESTAMP NOT NULL,
    interval_seconds INT       NOT NULL DEFAULT 5,
    status           TEXT      NOT NULL DEFAULT 'pending', -- pending|approved|denied
    user_id          TEXT,                -- populated on approval
    session_data     BLOB      NOT NULL
);
```

> `session_data` is an opaque JSON blob managed entirely by the passport package.
> Treat it as a `BLOB` / `BYTEA` column — store it and return it unchanged.

---

## Behaviour interfaces

### UserSessionProvider

Resolves the currently authenticated user from an HTTP request. Used by the
authorize endpoint to identify who is granting access.

```go
type UserSessionProvider interface {
    // Return (nil, nil) when no user is authenticated.
    // The server redirects to Config.LoginURL in that case.
    GetUser(ctx context.Context, r *http.Request) (sanctum.User, error)
}

// Example: read a session cookie and look up the user.
type CookieSessionProvider struct{ db *sql.DB }

func (p *CookieSessionProvider) GetUser(ctx context.Context, r *http.Request) (sanctum.User, error) {
    c, err := r.Cookie("session")
    if err != nil {
        return nil, nil // no session → nil, nil
    }
    return p.db.FindUserBySessionToken(ctx, c.Value)
}
```

### ConsentProvider

Manages user consent so the consent screen is only shown once per
client + scope combination.

```go
type ConsentProvider interface {
    IsConsentGranted(ctx context.Context, userID, clientID string, scopes []string) (bool, error)
    SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error
    RevokeConsent(ctx context.Context, userID, clientID string) error
}
```

**Consent flow:**

1. The authorize endpoint calls `IsConsentGranted`.
2. If `false`, the server redirects to:
   ```
   {ConsentURL}?client_id=…&scopes=…&return={original_authorize_url}
   ```
3. Your consent page shows the user what scopes are being requested.
4. On approval, your handler calls `SaveConsent` and redirects back to `?return=…`.

### UserInfoProvider

Returns OIDC claims for the `/oauth/userinfo` endpoint.

```go
type UserInfoProvider interface {
    // scopes is always empty in the current version — look up claims by user ID.
    // See the note below.
    GetUserInfo(ctx context.Context, user sanctum.User, scopes []string) (map[string]any, error)
}
```

> **Note:** Due to a limitation in fosite v0.49, the `scopes` slice passed to
> `GetUserInfo` is always empty. Look up the user's information from your own
> store using `user.GetID()` rather than filtering by scope.

```go
type MyUserInfoProvider struct{ db *sql.DB }

func (p *MyUserInfoProvider) GetUserInfo(ctx context.Context, user sanctum.User, _ []string) (map[string]any, error) {
    u, err := p.db.FindUser(ctx, user.GetID())
    if err != nil {
        return nil, err
    }
    return map[string]any{
        "name":  u.DisplayName,
        "email": u.Email,
    }, nil
}
```

---

## HTTP routes

`RegisterRoutes` mounts all endpoints onto a `*http.ServeMux`:

```go
mux := http.NewServeMux()
srv.RegisterRoutes(mux)
```

| Method | Path | Description |
|---|---|---|
| `GET` | `/oauth/authorize` | Authorization Code initiation |
| `POST` | `/oauth/token` | Token exchange (all grant types) |
| `POST` | `/oauth/revoke` | Token revocation (RFC 7009) |
| `GET/POST` | `/oauth/userinfo` | OIDC UserInfo endpoint (RFC 9068 §6) |
| `POST` | `/oauth/device/code` | Device Authorization (returns 501 until fosite RFC 8628 support) |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | JSON Web Key Set (public key) |

Mount on a sub-path if needed:

```go
// Serve auth on /auth/...
authMux := http.NewServeMux()
srv.RegisterRoutes(authMux)
mainMux.Handle("/auth/", http.StripPrefix("/auth", authMux))
```

---

## ResourceGuard

`ResourceGuard` validates RS256 JWT access tokens in downstream API services.
It does not require database access — only the issuer and public key.

### Static key

Use when the resource server and authorization server share the same process or
load the RSA public key from disk at startup.

```go
guard := passport.NewResourceGuard("https://auth.example.com", &rsaKey.PublicKey)
```

### Remote JWKS

Use when the resource server is a separate service. The JWKS is fetched from
`/.well-known/jwks.json` and cached (default TTL: 1 hour). Concurrent refresh
requests are deduplicated to avoid thundering-herd cache stampedes.

```go
guard := passport.NewRemoteResourceGuard(
    "https://auth.example.com",
    "https://auth.example.com/.well-known/jwks.json",
    passport.WithCacheTTL(30*time.Minute),
    passport.WithHTTPClient(myHTTPClient),
)
```

### Middleware

```go
mux.Handle("/api/data", guard.Middleware(http.HandlerFunc(dataHandler)))
```

On success: stores `*passport.TokenClaims` in the request context and calls
`next`.  
On failure: writes `{"error":"unauthorized"}` with `401 Unauthorized`.

### Manual validation

```go
claims, err := guard.Authenticate(r)
switch {
case errors.Is(err, passport.ErrUnauthorized):
    // No Bearer token in the request
case errors.Is(err, passport.ErrTokenExpired):
    // Token signature is valid but exp is in the past
case errors.Is(err, passport.ErrInvalidToken):
    // Malformed token, wrong issuer, bad signature, or wrong algorithm
case err != nil:
    // Unexpected error (e.g. JWKS fetch failure)
}
```

### Reading claims from context

```go
func dataHandler(w http.ResponseWriter, r *http.Request) {
    claims := passport.ClaimsFromContext(r.Context())
    // claims is nil when the request bypassed the middleware

    if !claims.HasScope("data:read") {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    fmt.Fprintf(w, "hello user %s (client %s)", claims.Subject, claims.ClientID)
}
```

`TokenClaims` fields:

```go
type TokenClaims struct {
    Subject   string         // "sub" claim — the user's ID
    ClientID  string         // "client_id" claim
    Scopes    []string       // "scp" claim, space-split
    Issuer    string         // "iss" claim
    ExpiresAt time.Time
    Extra     map[string]any // all other claims
}

// HasScope returns true only when every requested scope is present.
claims.HasScope("read")           // single scope
claims.HasScope("read", "write")  // all must be present
```

---

## OAuthClient reference

```go
type OAuthClient struct {
    // ID is the OAuth2 client_id. Must be unique.
    ID string

    // SecretHash is a bcrypt hash of the client secret.
    // Leave empty for public clients (no secret required).
    SecretHash string

    // Name is a human-readable label shown on consent screens.
    Name string

    // RedirectURIs lists allowed redirect targets.
    RedirectURIs []string

    // GrantTypes lists the grant types this client may use:
    //   "authorization_code", "client_credentials", "refresh_token",
    //   "urn:ietf:params:oauth:grant-type:device_code"
    GrantTypes []string

    // Scopes lists the scopes this client is permitted to request.
    Scopes []string

    // Public marks clients with no secret (SPAs, CLIs).
    // PKCE S256 is required for all public clients.
    Public bool
}
```

---

## Config reference

```go
type Config struct {
    // Issuer is the OAuth2/OIDC issuer URL. Required.
    // e.g. "https://auth.example.com"
    Issuer string

    // LoginURL is where unauthenticated users are redirected.
    // The server appends ?return=<original_authorize_url>.
    LoginURL string

    // ConsentURL is where users are redirected for consent.
    // The server appends ?client_id=…&scopes=…&return=<authorize_url>.
    ConsentURL string

    // VerificationURI is the device verification page (device grant).
    VerificationURI string

    // GlobalSecret is used for HMAC signing of refresh tokens and
    // authorization codes. Must be at least 32 bytes. Required.
    GlobalSecret []byte

    // AccessTokenTTL  default: 1 hour
    // RefreshTokenTTL default: 30 days
    // AuthCodeTTL     default: 10 minutes
    // DeviceCodeTTL   default: 5 minutes
    AccessTokenTTL  time.Duration
    RefreshTokenTTL time.Duration
    AuthCodeTTL     time.Duration
    DeviceCodeTTL   time.Duration

    // DeviceInterval is the minimum polling interval in seconds. Default: 5.
    DeviceInterval int
}
```

```go
cfg := passport.DefaultConfig("https://auth.example.com")
// Populate before use:
cfg.GlobalSecret = secret32bytes
cfg.LoginURL    = "https://auth.example.com/login"
cfg.ConsentURL  = "https://auth.example.com/consent"
```

---

## Error reference

### Server / storage errors

| Error | Returned by | When |
|---|---|---|
| `ErrClientNotFound` | `ClientStore` | No client matches the requested `client_id` |
| `ErrCodeNotFound` | `AuthorizationCodeStore` | Code does not exist |
| `ErrCodeInvalidated` | `AuthorizationCodeStore` | Code was already exchanged (`Active == false`) |
| `ErrTokenNotFound` | `AccessTokenStore`, `RefreshTokenStore` | Signature not found |
| `ErrTokenInactive` | `RefreshTokenStore` | Token exists but `Active == false` |
| `ErrDeviceNotFound` | `DeviceStore` | Device code or user code not found |

### ResourceGuard errors

| Error | When |
|---|---|
| `ErrUnauthorized` | No `Authorization: Bearer` header in the request |
| `ErrInvalidToken` | Token is malformed, wrong algorithm, bad signature, or wrong issuer |
| `ErrTokenExpired` | Token signature is valid but `exp` is in the past |

```go
claims, err := guard.Authenticate(r)
switch {
case errors.Is(err, passport.ErrUnauthorized): // 401 — no token
case errors.Is(err, passport.ErrTokenExpired):  // 401 — prompt re-login
case errors.Is(err, passport.ErrInvalidToken):  // 401 — reject
}
```

---

## Laravel comparison

| Laravel Passport | Go passport |
|---|---|
| `php artisan passport:install` | `passport.NewServer(cfg, stores..., key)` |
| `HasApiTokens` trait on User | Implement `sanctum.User` (`GetID() string`) |
| `Client` model | `passport.OAuthClient` struct |
| `Route::get('/oauth/authorize')` | `GET /oauth/authorize` (registered by `RegisterRoutes`) |
| `Route::post('/oauth/token')` | `POST /oauth/token` |
| `Route::post('/oauth/revoke')` | `POST /oauth/revoke` |
| `Route::get('/oauth/userinfo')` | `GET/POST /oauth/userinfo` |
| `passport.key` / `passport-public.key` | `*rsa.PrivateKey` passed to `NewServer` |
| `Passport::tokensExpireIn(…)` | `Config.AccessTokenTTL` |
| `Passport::refreshTokensExpireIn(…)` | `Config.RefreshTokenTTL` |
| `auth()->user()` in controller | `passport.ClaimsFromContext(r.Context()).Subject` |
| `$request->user()->token()` | `passport.ClaimsFromContext(r.Context())` |
| `$request->user()->tokenCan('scope')` | `claims.HasScope("scope")` |
| `auth:api` middleware | `guard.Middleware(next)` |
| `ResourceServer` | `passport.NewResourceGuard(issuer, pubKey)` |
| Remote resource server | `passport.NewRemoteResourceGuard(issuer, jwksURL)` |
| `Passport::routes()` | `srv.RegisterRoutes(mux)` |
| `php artisan passport:client --public` | `OAuthClient{Public: true, GrantTypes: ["authorization_code"]}` |
| `php artisan passport:client --client` | `OAuthClient{GrantTypes: ["client_credentials"]}` |
| `ConsentResponse` / consent screen | Implement `ConsentProvider`; redirect to `Config.ConsentURL` |
| `PersonalAccessClient` | Not applicable — use `sanctum` for personal access tokens |
