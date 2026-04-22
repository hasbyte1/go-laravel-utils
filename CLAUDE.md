# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`go-laravel-utils` (module: `github.com/hasbyte1/go-laravel-utils`) is a Go library that ports core Laravel PHP framework utilities to Go. It is interface-first, DB-agnostic, and designed for Laravel wire-format compatibility (so Go and PHP services can share encrypted payloads and password hashes).

## Commands

```bash
# Run all tests (always use -race)
go test -race ./...

# Run tests for a single package
go test -race ./collections/...
go test -race ./sanctum/...

# Run a single test
go test -race -run TestFunctionName ./pkg/...

# Run benchmarks
go test -bench=. -benchmem ./collections/
go test -bench=. -benchmem ./hashing/

# Run fuzz tests (runs until cancelled)
go test -fuzz=FuzzCBCEncrypt ./encryption/

# Publish a new version (reads #major/#minor from commit message, otherwise bumps patch)
./publish
./publish major   # force major bump
./publish minor   # force minor bump
```

No Makefile; no lint config present — use standard `go vet ./...` and `go build ./...`.

## Architecture

Eight packages, each independently importable:

| Package | Purpose |
|---|---|
| `collections` | Generic `Collection[T]` with 50+ chainable methods; all methods return new instances (immutable) |
| `arr` | Slice helpers and dot-notation map access |
| `encryption` | AES-CBC and AES-GCM encryption with Laravel-compatible wire format |
| `hashing` | Bcrypt, Argon2i, Argon2id behind a common `Hasher` interface; driver `Manager` enables `NeedsRehash()` upgrades |
| `sanctum` | Token and SPA cookie authentication inspired by Laravel Sanctum |
| `sanctum/inmemory` | Thread-safe in-memory implementations of the Sanctum repository interfaces, for use in tests |
| `passport` | OAuth2/OIDC authorization server inspired by Laravel Passport (wraps ory/fosite internally) |
| `passport/inmemory` | Thread-safe in-memory implementations of all passport storage interfaces, for use in tests |

### Key patterns

**Interface-first.** Every package exposes the behaviour as an interface (`Encrypter`, `Hasher`, `TokenRepository`, `UserProvider`, `SessionAuthenticator`, `Enumerable[T]`). Callers depend on the interface, not the concrete type.

**Generics.** `Collection[T]` and the top-level package functions (`Map[T,U]`, `Reduce[T,U]`, `GroupBy[T,K]`, `Zip[A,B]`, etc.) require Go 1.18+. The module declares `go 1.24.0`.

**Functional options.** Configuration is passed via options functions (e.g., `WithPreviousKeys()`, `WithTokenValidator()`, `WithEventListener()`). Constructors work with zero options.

**Wire-format compatibility.** Encryption payloads are base64-encoded JSON with `iv`, `value`, and `mac`/`tag` fields — the exact format Laravel produces. Password hashes use the standard PHC format, readable by Laravel's Argon2 driver.

### Sanctum authentication flow

Tokens are stored as `sha256(secret)` only — the plaintext is irrecoverable after creation. The token string format is `<uuid>|<secret>`, where the UUID prefix allows O(1) DB lookup without exposing the secret. Consumers must implement `TokenRepository` and `UserProvider`; `sanctum/inmemory` provides ready-made test doubles.

### `passport` package

OAuth2/OIDC authorization server wrapping [ory/fosite](https://github.com/ory/fosite). Consumers implement five storage interfaces (`ClientStore`, `AuthorizationCodeStore`, `AccessTokenStore`, `RefreshTokenStore`, `DeviceStore`) and three behaviour interfaces (`UserSessionProvider`, `ConsentProvider`, `UserInfoProvider`). fosite is hidden behind an internal `adapter`; consumers never import fosite.

**Key files:** `server.go` (construction + `ApproveDevice`/`DenyDevice`), `handlers.go` (HTTP layer), `oidc.go` (userinfo/discovery/JWKS), `resource.go` (`ResourceGuard`), `adapter.go` (all fosite storage interface implementations).

**Grant types:** Authorization Code + PKCE (S256 enforced for public clients), Client Credentials, Refresh Token. Device Authorization is modeled in the storage layer but requires a fosite version with `RFC8628DeviceAuthorizationGrantFactory` to be fully wired.

**JWT signing:** RS256 (`*rsa.PrivateKey` supplied at construction). Public key exposed at `/.well-known/jwks.json`. `ResourceGuard` validates JWT access tokens in downstream API services — static key or remote JWKS with cache.

**Run tests:**
```bash
go test -race ./passport/...
```

### Security invariants to preserve

- Always verify MAC/GCM tag **before** decryption (padding oracle prevention).
- Use `crypto/subtle.ConstantTimeCompare` for all token/CSRF comparisons.
- Generate IVs/nonces from `crypto/rand` on every `Encrypt` call.
- Hashing defaults: Bcrypt cost 12, Argon2 m=64MiB t=3 p=2 — do not lower these.
- Clone keys on ingestion so external mutations cannot affect the encrypter state.
