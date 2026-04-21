# passport — OAuth2 / OIDC Server Design

**Date:** 2026-04-21  
**Status:** Approved  
**Scope:** New `passport` package + `passport/inmemory` sub-package in `go-laravel-utils`

---

## Overview

`passport` is a Laravel Passport-inspired OAuth2 authorization server for Go. It wraps [ory/fosite](https://github.com/ory/fosite) as an internal implementation detail — fosite never appears in the public API. Consumers implement plain Go storage interfaces; an internal adapter translates to fosite's storage contracts.

The package shares `sanctum.User` (the `GetID() string` interface) as the common user identity contract.

### Grant types supported
- Authorization Code + PKCE (RFC 7636)
- Client Credentials
- Refresh Token
- Device Authorization (RFC 8628)

### OIDC
Basic OIDC: ID tokens (JWT, RS256 or ES256), `userinfo` endpoint, and `/.well-known/openid-configuration` discovery document.

### Token format
JWT access tokens only, signed with RS256 or ES256. The consumer supplies a `crypto.Signer` (RSA or EC private key) at construction time.

### HTTP layer
Standard `net/http` handlers only. Zero router dependency. Consumers mount handlers onto their own router (chi, gorilla, echo, etc.) at paths of their choosing. A `RegisterRoutes(*http.ServeMux)` convenience method mounts at the default paths.

---

## Package Structure

```
passport/
├── doc.go
├── config.go        — Config struct + DefaultConfig()
├── server.go        — Server struct, NewServer(), handler registration, ApproveDevice/DenyDevice
├── client.go        — Client-related types (OAuthClient) + ClientStore interface
├── store.go         — AuthorizationCodeStore, AccessTokenStore, RefreshTokenStore, DeviceStore interfaces
├── models.go        — Plain Go structs: AuthorizationCode, AccessToken, RefreshToken, DeviceCode
├── token.go         — JWT key loading helpers (RSA/EC)
├── user.go          — UserSessionProvider, ConsentProvider, UserInfoProvider interfaces
├── handlers.go      — http.Handler implementations (thin fosite delegation)
├── oidc.go          — UserInfo + discovery + JWKS handlers
├── resource.go      — ResourceGuard: JWT validation for resource servers
├── errors.go        — Sentinel errors
└── inmemory/
    ├── doc.go
    └── store.go     — Thread-safe in-memory implementations of all storage interfaces
```

**Key principle:** fosite is an internal detail. An unexported `adapter` struct implements fosite's storage interfaces by delegating to the consumer-facing interfaces. Consumers never import fosite.

---

## Storage Interfaces

All interfaces use only `passport`-owned types — no fosite imports required by consumers.

```go
// ClientStore — client application registry
type ClientStore interface {
    GetClient(ctx context.Context, id string) (*OAuthClient, error)
}

type AuthorizationCodeStore interface {
    CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
    GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
    DeleteAuthorizationCode(ctx context.Context, code string) error
}

type AccessTokenStore interface {
    CreateAccessToken(ctx context.Context, token *AccessToken) error
    GetAccessToken(ctx context.Context, signature string) (*AccessToken, error)
    DeleteAccessToken(ctx context.Context, signature string) error
    DeleteAccessTokensBySubject(ctx context.Context, subject string) error
}

type RefreshTokenStore interface {
    CreateRefreshToken(ctx context.Context, token *RefreshToken) error
    GetRefreshToken(ctx context.Context, signature string) (*RefreshToken, error)
    DeleteRefreshToken(ctx context.Context, signature string) error
    DeleteRefreshTokensBySubject(ctx context.Context, subject string) error
}

type DeviceStore interface {
    CreateDeviceCode(ctx context.Context, req *DeviceCode) error
    GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
    GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
    UpdateDeviceCode(ctx context.Context, req *DeviceCode) error
    DeleteDeviceCode(ctx context.Context, deviceCode string) error
}
```

PKCE session data is carried inside `AuthorizationCode` (the `CodeChallenge` / `CodeChallengeMethod` fields) rather than a separate store. The internal adapter reads/writes PKCE state through `AuthorizationCodeStore`.

---

## Data Models

```go
type OAuthClient struct {
    ID           string
    SecretHash   string   // bcrypt hash of the client secret — fosite uses bcrypt for comparison; never store plaintext
    Name         string
    RedirectURIs []string
    GrantTypes   []string // "authorization_code" | "client_credentials" | "refresh_token" | "urn:ietf:params:oauth:grant-type:device_code"
    Scopes       []string
    Public       bool     // public client = no secret, PKCE required
}

type AuthorizationCode struct {
    Code                string
    ClientID            string
    UserID              string
    RedirectURI         string
    Scopes              []string
    ExpiresAt           time.Time
    CodeChallenge       string
    CodeChallengeMethod string // "S256" or "plain"
    Nonce               string // OIDC
}

type AccessToken struct {
    Signature string    // JWT signature segment, used as storage key
    ClientID  string
    UserID    string    // empty for client_credentials
    Scopes    []string
    ExpiresAt time.Time
}

type RefreshToken struct {
    Signature string
    ClientID  string
    UserID    string
    Scopes    []string
    ExpiresAt time.Time
    Active    bool
}

type DeviceCode struct {
    DeviceCode string
    UserCode   string
    ClientID   string
    Scopes     []string
    ExpiresAt  time.Time
    Interval   int    // polling interval in seconds
    Status     string // "pending" | "approved" | "denied"
    UserID     string // populated when Status == "approved"
}
```

---

## Config

```go
type Config struct {
    Issuer           string        // e.g. "https://auth.example.com" — required
    LoginURL         string        // redirect target when user is not authenticated; Server appends ?return=<original_authorize_url>
    ConsentURL       string        // redirect target for consent; Server appends ?client_id=…&scopes=…&return=<original_authorize_url>
    VerificationURI  string        // device verification page URL (consumer-owned); returned as verification_uri in device authorization response — required if device grant is used
    AccessTokenTTL   time.Duration // default 1 hour
    RefreshTokenTTL  time.Duration // default 30 days
    AuthCodeTTL      time.Duration // default 10 minutes
    DeviceCodeTTL    time.Duration // default 5 minutes
    DeviceInterval   int           // device polling interval seconds, default 5
}
```

---

## Server Construction

```go
// UserSessionProvider resolves the authenticated user from an inbound HTTP request.
// Return (nil, nil) when no authenticated user is present — the Server redirects to LoginURL.
type UserSessionProvider interface {
    GetUser(ctx context.Context, r *http.Request) (sanctum.User, error)
}

// ConsentProvider manages the consent lifecycle.
type ConsentProvider interface {
    IsConsentGranted(ctx context.Context, userID, clientID string, scopes []string) (bool, error)
    SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error
    RevokeConsent(ctx context.Context, userID, clientID string) error
}

// UserInfoProvider returns OIDC claims for a user given the granted scopes.
type UserInfoProvider interface {
    GetUserInfo(ctx context.Context, user sanctum.User, scopes []string) (map[string]any, error)
}

func NewServer(
    cfg         Config,
    clients     ClientStore,
    authCodes   AuthorizationCodeStore,
    accessToks  AccessTokenStore,
    refreshToks RefreshTokenStore,
    devices     DeviceStore,
    sessions    UserSessionProvider,
    consent     ConsentProvider,
    userInfo    UserInfoProvider,
    users       sanctum.UserProvider,
    key         crypto.Signer,         // RSA or EC private key for JWT signing
    opts        ...ServerOption,
) (*Server, error)
```

---

## HTTP Endpoints

| Handler method | Default path | Purpose |
|---|---|---|
| `HandleAuthorize()` | `GET /oauth/authorize` | Authorization code initiation |
| `HandleToken()` | `POST /oauth/token` | All grant type token exchanges |
| `HandleRevoke()` | `POST /oauth/revoke` | Token revocation (RFC 7009) |
| `HandleUserInfo()` | `GET /oauth/userinfo` | OIDC userinfo |
| `HandleDeviceAuthorization()` | `POST /oauth/device/code` | Device authorization request |
| `HandleDiscovery()` | `GET /.well-known/openid-configuration` | OIDC discovery document |
| `HandleJWKS()` | `GET /.well-known/jwks.json` | Public key set |

```go
// RegisterRoutes mounts all handlers at the default paths above.
func (s *Server) RegisterRoutes(mux *http.ServeMux)
```

The device verification UI is **not** served by `passport` — the consumer owns that page. After the user enters the `user_code`, the consumer calls:

```go
func (s *Server) ApproveDevice(ctx context.Context, userCode string, user sanctum.User) error
func (s *Server) DenyDevice(ctx context.Context, userCode string) error
```

---

## Authorization Code Flow

```
Browser                    passport.Server              Consumer app
   |                             |                           |
   |-- GET /oauth/authorize ---->|                           |
   |                             |-- GetUser(r) ----------->|
   |                             |<-- nil (not logged in) --|
   |<-- 302 → LoginURL?return=… -|                           |
   |                             |                           |
   |  (user logs in via consumer routes)                     |
   |                             |                           |
   |-- GET /oauth/authorize ---->|                           |
   |                             |-- GetUser(r) ----------->|
   |                             |<-- user -----------------|
   |                             |-- IsConsentGranted() --->|
   |                             |<-- false -----------------|
   |<-- 302 → ConsentURL?… ------|                           |
   |                             |                           |
   |  (user approves via consumer consent page)              |
   |                             |<-- SaveConsent() ---------|
   |-- GET /oauth/authorize ---->|                           |
   |                             |-- IsConsentGranted() --->|
   |                             |<-- true -----------------|
   |<-- 302 → redirect_uri?code= |                           |
```

---

## Device Authorization Flow

```
Device                     passport.Server              User's browser
   |                             |                           |
   |-- POST /oauth/device/code ->|                           |
   |<-- {device_code, user_code, verification_uri} ----------|
   |                             |                           |
   |-- poll POST /oauth/token -->|                           |
   |<-- 400 authorization_pending|                           |
   |                             |                           |
   |                    user visits verification_uri          |
   |                    enters user_code (consumer UI)        |
   |                             |<-- ApproveDevice() -------|
   |                             |                           |
   |-- poll POST /oauth/token -->|                           |
   |<-- 200 {access_token, …} ---|                           |
```

---

## ResourceGuard

For API services that validate JWT access tokens without running the auth server.

```go
type TokenClaims struct {
    Subject   string
    ClientID  string
    Scopes    []string
    Issuer    string
    ExpiresAt time.Time
    Extra     map[string]any
}

func (c *TokenClaims) HasScope(scopes ...string) bool

// Static public key (same process or loaded from disk):
func NewResourceGuard(issuer string, key crypto.PublicKey) *ResourceGuard

// Remote JWKS with automatic caching and key-rotation refresh:
func NewRemoteResourceGuard(issuer, jwksURL string, opts ...ResourceGuardOption) *ResourceGuard

func (g *ResourceGuard) Authenticate(r *http.Request) (*TokenClaims, error)
func (g *ResourceGuard) Middleware(next http.Handler) http.Handler

func ClaimsFromContext(ctx context.Context) *TokenClaims
```

Functional options: `WithHTTPClient(*http.Client)`, `WithCacheTTL(time.Duration)`.

---

## `passport/inmemory`

Single `Store` struct satisfies all five storage interfaces. Includes `ConsentStore` and `SessionStore` so a complete server can be wired in tests with zero external dependencies.

```go
store := inmemory.New()
store.AddClient(&passport.OAuthClient{ /* … */ })

sessions := inmemory.NewSessionStore()
sessions.Set("cookie-value", myUser)

consent := inmemory.NewConsentStore() // auto-approves all requests

srv, _ := passport.NewServer(cfg, store, store, store, store, store,
    sessions, consent, userInfo, users, key)
```

---

## Security Properties

- PKCE S256 enforced for public clients; plain method rejected by default.
- `crypto/rand` for all random generation (device codes, auth codes).
- Auth codes are single-use: deleted on first exchange (replay prevention).
- Refresh token rotation: old refresh token deleted on each use.
- JWT signing key never leaves the `Server`; only the public key is exposed via JWKS.
- JWKS cache in `ResourceGuard` re-fetches on unknown `kid` to handle key rotation without restart.
- Device polling interval enforced server-side; `slow_down` response sent on over-polling.
