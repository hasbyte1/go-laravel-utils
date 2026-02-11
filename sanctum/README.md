# sanctum

Package `sanctum` provides lightweight personal access token (PAT) and SPA cookie
authentication for `net/http`-compatible Go services, modelled after Laravel Sanctum.

```
go get github.com/hasbyte1/go-laravel-utils/sanctum
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [Architecture](#architecture)
3. [Token lifecycle](#token-lifecycle)
   - [Token format](#token-format)
   - [Creating tokens](#creating-tokens)
   - [Authenticating tokens](#authenticating-tokens)
   - [Revoking tokens](#revoking-tokens)
   - [Listing tokens](#listing-tokens)
   - [Pruning expired tokens](#pruning-expired-tokens)
4. [Abilities (scopes)](#abilities-scopes)
5. [Guard](#guard)
   - [Bearer token auth](#bearer-token-auth)
   - [Session auth (SPA)](#session-auth-spa)
   - [CSRF protection](#csrf-protection)
6. [Middleware](#middleware)
7. [Auth context](#auth-context)
8. [Config reference](#config-reference)
9. [Interfaces](#interfaces)
10. [Event listeners & validators](#event-listeners--validators)
11. [Error reference](#error-reference)
12. [Porting guide](#porting-guide)
    - [Node.js / TypeScript](#nodejs--typescript)
    - [Python](#python)
13. [Laravel comparison](#laravel-comparison)

---

## Quick start

```go
import (
    "github.com/hasbyte1/go-laravel-utils/sanctum"
    "github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

// 1. Wire up dependencies
repo  := inmemory.New()          // swap for a real DB in production
users := inmemory.NewUserStore() // swap for your user store

cfg := sanctum.DefaultConfig()
svc := sanctum.NewTokenService(repo, users, cfg)

// 2. Create a personal access token for user "user-1"
result, err := svc.CreateToken(ctx, "user-1", sanctum.CreateTokenOptions{
    Name:      "My App",
    Abilities: []string{"read", "write"},
})
// Deliver result.PlainText to the user ONCE — it cannot be recovered later.
fmt.Println(result.PlainText) // "550e8400-…|abc123…"

// 3. Authenticate a request
user, token, err := svc.AuthenticateToken(ctx, result.PlainText)

// 4. Check abilities
sanctum.Can(token.Abilities, "read")   // true
sanctum.CanAll(token.Abilities, "read", "write") // true
```

---

## Architecture

```
             HTTP request
                  │
            ┌─────▼──────┐
            │   Guard    │  ← Authenticate / SPA session
            └─────┬──────┘
                  │
            ┌─────▼──────┐
            │TokenService│  ← Business logic
            └──┬───────┬─┘
               │       │
    ┌──────────▼─┐  ┌──▼────────────┐
    │TokenRepo   │  │UserProvider   │
    │(interface) │  │(interface)    │
    └────────────┘  └───────────────┘
```

`Guard` wraps a `TokenService` and plugs into `net/http` middleware. All storage is
delegated through interfaces (`TokenRepository`, `UserProvider`), keeping the core
logic independent of any database technology.

---

## Token lifecycle

### Token format

Plain-text tokens use the format `{uuid}|{base64url-secret}`:

```
550e8400-e29b-41d4-a716-446655440000|abc123defgh...
```

- The `uuid` part is the token ID used for fast O(1) look-up.
- The `secret` part is cryptographically random (40 bytes by default).
- Only `sha256(secret)` is stored in the database — **never** store the plain text.

### Creating tokens

```go
result, err := svc.CreateToken(ctx, userID, sanctum.CreateTokenOptions{
    Name:      "GitHub Actions",       // human-readable label
    Abilities: []string{"deploy"},     // empty → wildcard ["*"]
    ExpiresAt: &expiryTime,            // nil → Config.DefaultExpiry or never
})

fmt.Println(result.PlainText) // show to user once
token := result.Token         // persisted record (no plain text)
```

### Authenticating tokens

```go
user, token, err := svc.AuthenticateToken(ctx, bearerToken)
// err = ErrInvalidToken, ErrTokenExpired, ErrTokenNotFound, or a repo error
```

`AuthenticateToken` flow:
1. Parses `{id}|{secret}` format, looks up the token by ID.
2. Falls back to a hash-based lookup for tokens without the ID prefix.
3. Verifies `sha256(secret)` against the stored hash.
4. Checks expiry.
5. Loads the user via `UserProvider`.
6. Updates `LastUsedAt` (best-effort, does not fail auth on update error).

### Revoking tokens

```go
// Revoke a single token by ID
err := svc.RevokeToken(ctx, tokenID)

// Revoke all tokens for a user (e.g., "log out everywhere")
err = svc.RevokeAllTokens(ctx, userID)
```

### Listing tokens

```go
tokens, err := svc.ListTokens(ctx, userID)
for _, t := range tokens {
    fmt.Println(t.Name, t.CreatedAt, t.LastUsedAt)
}
```

### Pruning expired tokens

```go
n, err := svc.PruneExpired(ctx) // returns number of tokens removed
```

Call this periodically (cron job, scheduled task) to keep the token table lean.

---

## Abilities (scopes)

Abilities are string-valued permission labels attached to a token at creation time.
A single `"*"` grants all abilities (wildcard).

```go
sanctum.Can(token.Abilities, "reports:export")    // single ability check
sanctum.CanAll(token.Abilities, "read", "write")  // all must be present (AND)
sanctum.CanAny(token.Abilities, "admin", "owner") // at least one (OR)
```

Examples:

```go
token.Abilities = []string{"*"}
sanctum.Can(token.Abilities, "anything") // true — wildcard

token.Abilities = []string{"read", "export"}
sanctum.Can(token.Abilities, "write")  // false
sanctum.CanAny(token.Abilities, "write", "read") // true
```

---

## Guard

`Guard` is the main HTTP authentication entry-point. It tries Bearer token
authentication first, then falls back to session authentication (if configured).

```go
guard := sanctum.NewGuard(svc, csrfSvc,
    sanctum.WithTokenValidator(myIPValidator),
    sanctum.WithEventListener(myLogger),
    sanctum.WithSessionAuthenticator(mySessionAuth),
)
```

### Bearer token auth

Clients send:

```
Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000|abc123…
```

The Guard extracts and authenticates the token automatically.

### Session auth (SPA)

For SPA cookie-based authentication, implement `SessionAuthenticator`:

```go
type SessionAuthenticator interface {
    AuthenticateFromSession(ctx context.Context, r *http.Request) (User, error)
}
```

```go
guard := sanctum.NewGuard(svc, csrfSvc,
    sanctum.WithSessionAuthenticator(&myCookieAuth{}),
)
```

Session-authenticated requests bypass token ability checks in `RequireAbilities` and
`RequireAnyAbility` middleware — session users are assumed to have full access.

### CSRF protection

For session-authenticated SPAs, state-changing requests (POST, PUT, PATCH, DELETE)
require CSRF validation using the double-submit cookie pattern.

**Setup:**

```go
csrfSvc := sanctum.NewCSRFService(sanctum.DefaultConfig())
guard   := sanctum.NewGuard(svc, csrfSvc)
```

**SPA page load** (GET `/sanctum/csrf-cookie`):

```go
http.HandleFunc("/sanctum/csrf-cookie", func(w http.ResponseWriter, r *http.Request) {
    _, err := csrfSvc.IssueToken(w)
    // Sets a readable "XSRF-TOKEN" cookie (non-HttpOnly so JS can read it)
})
```

**SPA subsequent requests** (Axios, Fetch API):
- JavaScript must copy the `XSRF-TOKEN` cookie value into the `X-XSRF-TOKEN` request header.
- Axios does this automatically for `withCredentials: true` requests.

```javascript
// Axios — automatic CSRF header injection
axios.defaults.withCredentials = true;
await axios.get('/sanctum/csrf-cookie'); // sets cookie
await axios.post('/api/logout');         // X-XSRF-TOKEN header sent automatically
```

---

## Middleware

All middleware functions satisfy `func(http.Handler) http.Handler` and are compatible
with any `net/http`-based router (stdlib, chi, gorilla/mux, echo, etc.).

### `Authenticate`

Authenticates every request; injects `AuthContext` into the request context on success.

```go
mux.Handle("/api/", sanctum.Authenticate(guard)(apiHandler))
```

Returns `401 Unauthorized` (JSON) when auth fails.

### `RequireAbilities`

Ensures the token has **all** listed abilities (AND logic). Must be chained after `Authenticate`.

```go
mux.Handle("/api/deploy",
    sanctum.Authenticate(guard)(
        sanctum.RequireAbilities("deploy", "infra:write")(deployHandler),
    ),
)
```

Returns `403 Forbidden` when ability check fails.

### `RequireAnyAbility`

Ensures the token has **at least one** listed ability (OR logic).

```go
mux.Handle("/api/reports",
    sanctum.Authenticate(guard)(
        sanctum.RequireAnyAbility("admin", "reports:read")(reportsHandler),
    ),
)
```

### Using with chi router

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
r.Use(sanctum.Authenticate(guard))

r.Group(func(r chi.Router) {
    r.Use(sanctum.RequireAbilities("admin"))
    r.Get("/admin/users", listUsers)
})
```

---

## Auth context

After `Authenticate` succeeds, downstream handlers can retrieve the auth result from
the request context:

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    ac := sanctum.AuthContextFromRequest(r)
    if ac == nil {
        http.Error(w, "unauthenticated", http.StatusUnauthorized)
        return
    }

    fmt.Println(ac.User.GetID())  // authenticated user ID
    if ac.Token != nil {
        fmt.Println(ac.Token.Abilities)  // token abilities (nil for session auth)
    }
    fmt.Println(ac.IsSessionAuth) // true for SPA cookie auth
}
```

`AuthContext` fields:

```go
type AuthContext struct {
    User          User    // always present
    Token         *Token  // nil for session-authenticated requests
    IsSessionAuth bool    // true for session-based SPA auth
}
```

---

## Config reference

```go
type Config struct {
    // Random bytes used for token secrets (default: 40)
    TokenBytes int

    // Default token lifetime (zero = never expires)
    DefaultExpiry time.Duration

    // Host names for which cookie/session SPA auth is enabled
    StatefulDomains []string

    // CSRF cookie name (default: "XSRF-TOKEN")
    CSRFCookieName string

    // CSRF request header name (default: "X-XSRF-TOKEN")
    CSRFHeaderName string

    // Set the Secure flag on the CSRF cookie (enable in production)
    CSRFCookieSecure bool

    // SameSite attribute for the CSRF cookie ("Lax" | "Strict" | "None")
    CSRFCookieSameSite string
}
```

```go
cfg := sanctum.DefaultConfig()
// TokenBytes: 40, CSRFCookieName: "XSRF-TOKEN", CSRFHeaderName: "X-XSRF-TOKEN",
// CSRFCookieSameSite: "Lax"
```

---

## Interfaces

### `User`

Implement on your user model:

```go
type User interface {
    GetID() string
}

// Example
type AppUser struct { ID string; Email string }
func (u *AppUser) GetID() string { return u.ID }
```

### `TokenRepository`

Implement for your chosen storage backend (PostgreSQL, Redis, etc.):

```go
type TokenRepository interface {
    Create(ctx, token *Token) error
    FindByID(ctx, id string) (*Token, error)
    FindByHash(ctx, hash string) (*Token, error)
    UpdateLastUsedAt(ctx, id string, t time.Time) error
    Revoke(ctx, id string) error
    RevokeAll(ctx, userID string) error
    ListByUser(ctx, userID string) ([]*Token, error)
    PruneExpired(ctx) (int64, error)
}
```

See `sanctum/inmemory` for a reference implementation suitable for tests.

### `UserProvider`

```go
type UserProvider interface {
    FindByID(ctx context.Context, id string) (User, error)
}
```

Return `(nil, nil)` when the user is not found (not an error condition).

### `SessionAuthenticator`

```go
type SessionAuthenticator interface {
    AuthenticateFromSession(ctx context.Context, r *http.Request) (User, error)
}
```

Return `(nil, nil)` when the request carries no valid session.

---

## Event listeners & validators

### Event listeners

Register listeners to audit or log all authentication events:

```go
guard := sanctum.NewGuard(svc, csrfSvc,
    sanctum.WithEventListener(func(e sanctum.AuthEvent) {
        switch e.Type {
        case sanctum.EventAuthenticated:
            log.Printf("auth ok: user=%s token=%s", e.User.GetID(), e.Token.ID)
        case sanctum.EventFailed:
            log.Printf("auth failed: %v", e.Err)
        }
    }),
)
```

### Token validators

Run custom post-authentication checks (IP allow-listing, device fingerprinting, rate
limiting):

```go
guard := sanctum.NewGuard(svc, csrfSvc,
    sanctum.WithTokenValidator(func(
        ctx context.Context,
        r *http.Request,
        user sanctum.User,
        token *sanctum.Token,
    ) error {
        if !isAllowedIP(r.RemoteAddr) {
            return errors.New("IP not allowed")
        }
        return nil
    }),
)
```

Multiple validators are called in order; the first error aborts the chain.

---

## Error reference

| Error | HTTP status | When |
|---|---|---|
| `ErrUnauthorized` | 401 | No token or session found |
| `ErrInvalidToken` | 401 | Token string is malformed or hash mismatch |
| `ErrTokenExpired` | 401 | Token has passed its `ExpiresAt` |
| `ErrTokenNotFound` | 401 | Token ID not in repository |
| `ErrForbidden` | 403 | Token lacks required ability |
| `ErrInvalidCSRFToken` | 403 | CSRF cookie is missing or empty |
| `ErrCSRFMismatch` | 403 | CSRF header does not match cookie |

```go
user, _, err := svc.AuthenticateToken(ctx, bearer)
switch {
case errors.Is(err, sanctum.ErrTokenExpired):
    // prompt user to create a new token
case errors.Is(err, sanctum.ErrInvalidToken):
    // token was tampered or malformed
case err != nil:
    // storage error
}
```

---

## Porting guide

### Node.js / TypeScript

```typescript
// sanctum.ts — personal access token core
import crypto from "crypto";

interface User { getId(): string; }
interface Token {
  id: string; userId: string; name: string; hash: string;
  abilities: string[]; expiresAt?: Date; lastUsedAt?: Date;
}

function hashToken(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

function generateToken(
  userId: string, name: string, abilities: string[], expiresAt?: Date
): { plainText: string; token: Token } {
  const id     = crypto.randomUUID();
  const secret = crypto.randomBytes(40).toString("base64url");
  const hash   = hashToken(secret);
  return {
    plainText: `${id}|${secret}`,
    token: { id, userId, name, hash, abilities, expiresAt },
  };
}

function can(abilities: string[], ability: string): boolean {
  return abilities.includes("*") || abilities.includes(ability);
}

function canAll(abilities: string[], ...required: string[]): boolean {
  return required.every(a => can(abilities, a));
}

function canAny(abilities: string[], ...required: string[]): boolean {
  return required.some(a => can(abilities, a));
}

// Express.js middleware
import type { Request, Response, NextFunction } from "express";

function authenticate(repo: TokenRepository, users: UserStore) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers.authorization ?? "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "unauthenticated" });

    const plain = auth.slice(7);
    const [id, secret] = plain.split("|", 2);
    if (!id || !secret) return res.status(401).json({ error: "invalid token" });

    const token = await repo.findById(id);
    if (!token) return res.status(401).json({ error: "token not found" });
    if (hashToken(secret) !== token.hash) return res.status(401).json({ error: "invalid token" });
    if (token.expiresAt && token.expiresAt < new Date())
      return res.status(401).json({ error: "token expired" });

    const user = await users.findById(token.userId);
    if (!user) return res.status(401).json({ error: "user not found" });

    (req as any).auth = { user, token };
    next();
  };
}
```

### Python

```python
# sanctum.py — personal access token core
import hashlib, os, uuid, base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Token:
    id: str
    user_id: str
    name: str
    hash: str
    abilities: list[str]
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.utcnow() > self.expires_at


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_token(user_id: str, name: str, abilities: list[str],
                   expires_at: Optional[datetime] = None):
    token_id = str(uuid.uuid4())
    secret   = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    plain    = f"{token_id}|{secret}"
    token    = Token(id=token_id, user_id=user_id, name=name,
                     hash=hash_token(secret), abilities=abilities,
                     expires_at=expires_at)
    return plain, token


def can(abilities: list[str], ability: str) -> bool:
    return "*" in abilities or ability in abilities


def can_all(abilities: list[str], *required: str) -> bool:
    return all(can(abilities, a) for a in required)


def can_any(abilities: list[str], *required: str) -> bool:
    return any(can(abilities, a) for a in required)


# FastAPI middleware example
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer

class SanctumAuth:
    def __init__(self, repo, users):
        self.repo  = repo
        self.users = users

    async def __call__(self, request: Request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(401, "unauthenticated")
        plain = auth[7:]
        parts = plain.split("|", 1)
        if len(parts) != 2:
            raise HTTPException(401, "invalid token")
        token_id, secret = parts
        token = await self.repo.find_by_id(token_id)
        if not token or hash_token(secret) != token.hash:
            raise HTTPException(401, "invalid token")
        if token.is_expired():
            raise HTTPException(401, "token expired")
        user = await self.users.find_by_id(token.user_id)
        if not user:
            raise HTTPException(401, "user not found")
        return user, token
```

---

## Laravel comparison

| Laravel Sanctum | Go sanctum |
|---|---|
| `$user->createToken($name, $abilities)` | `svc.CreateToken(ctx, userID, opts)` |
| `$tokenResult->plainTextToken` | `result.PlainText` |
| `PersonalAccessToken` model | `sanctum.Token` struct |
| `HasApiTokens` trait on User | Implement `sanctum.User` interface |
| `$token->can($ability)` | `sanctum.Can(token.Abilities, ability)` |
| `$token->cant($ability)` | `!sanctum.Can(token.Abilities, ability)` |
| `PersonalAccessToken::findToken($token)` | `svc.AuthenticateToken(ctx, bearer)` |
| `$user->tokens()->delete()` | `svc.RevokeAllTokens(ctx, userID)` |
| `$token->delete()` | `svc.RevokeToken(ctx, tokenID)` |
| `PersonalAccessToken::pruneExpired()` | `svc.PruneExpired(ctx)` |
| `auth()->user()` in controller | `sanctum.AuthContextFromRequest(r).User` |
| `auth()->user()->currentAccessToken()` | `sanctum.AuthContextFromRequest(r).Token` |
| `auth('sanctum')->check()` | `sanctum.AuthContextFromRequest(r) != nil` |
| Sanctum middleware `auth:sanctum` | `sanctum.Authenticate(guard)` |
| `abilities` middleware | `sanctum.RequireAbilities(...)` |
| `EnsureFrontendRequestsAreStateful` | `sanctum.WithSessionAuthenticator(sa)` |
| CSRF cookie `XSRF-TOKEN` | `csrfSvc.IssueToken(w)` |
| `config('sanctum.expiration')` | `Config.DefaultExpiry` |
| `config('sanctum.token_prefix')` | No prefix; format is `{uuid}\|{secret}` |
| `TokenRepository` (custom driver) | `sanctum.TokenRepository` interface |
