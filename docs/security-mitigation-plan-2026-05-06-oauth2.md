# Security Mitigation Plan — OAuth2/Passport Package

**Date:** 2026-05-06  
**Reference audit:** `docs/security-audit-2026-05-06-oauth2.md`  
**Priority:** Address HIGH finding before next production deployment; MEDIUM before next minor release.

---

## Priority 1 — HIGH: Missing JWT Audience Validation

**Timeline:** Before next production deployment  
**Effort:** ~4 hours  
**Files to change:** `passport/models.go`, `passport/adapter.go`, `passport/resource.go`, `passport/config.go`

### Task 1.1 — Add `Audience` field to `OAuthClient`

In `passport/models.go`, add:

```go
type OAuthClient struct {
    // ... existing fields ...

    // Audience lists the resource servers this client's tokens are intended for.
    // e.g. ["https://api.example.com"]. Leave empty for single-service deployments.
    Audience []string
}
```

### Task 1.2 — Implement `GetAudience()` in `fositeClient`

In `passport/adapter.go`, replace:

```go
func (fc *fositeClient) GetAudience() fosite.Arguments { return fosite.Arguments{} }
```

With:

```go
func (fc *fositeClient) GetAudience() fosite.Arguments {
    if len(fc.c.Audience) > 0 {
        return fosite.Arguments(fc.c.Audience)
    }
    return fosite.Arguments{}
}
```

### Task 1.3 — Add `WithAudience` option to `ResourceGuard`

In `passport/resource.go`, add:

```go
// WithAudience sets the expected audience claim for this resource server.
// When set, tokens must contain a matching aud claim to be accepted.
// Strongly recommended for multi-service deployments.
func WithAudience(aud string) ResourceGuardOption {
    return func(g *ResourceGuard) { g.audience = aud }
}
```

Add `audience string` to the `ResourceGuard` struct.

### Task 1.4 — Validate `aud` in `mapToClaims`

In `passport/resource.go`, after issuer validation, add audience validation:

```go
// After iss check:
if g.audience != "" {
    if err := validateAudience(payload["aud"], g.audience); err != nil {
        return nil, err
    }
}
```

Implement `validateAudience` to handle both string and `[]any` representations of the claim, returning `ErrInvalidToken` on mismatch.

### Task 1.5 — Add `ErrAudienceMismatch` sentinel

In `passport/errors.go`, add:

```go
var ErrAudienceMismatch = errors.New("passport: token audience does not match this resource server")
```

### Task 1.6 — Tests

- Test that a token issued for audience `A` is rejected by a `ResourceGuard` configured for audience `B`.
- Test that a token with no `aud` claim is rejected when `WithAudience` is configured.
- Test that a `ResourceGuard` without `WithAudience` still accepts tokens (backward compatibility).
- Test multi-value `aud` (array).

### Version bump

This is a non-breaking addition to `ResourceGuard` (new option, optional). Bump patch → minor since `OAuthClient.Audience` is a new field and `fositeClient.GetAudience()` behavior changes.

---

## Priority 2 — MEDIUM: X-Forwarded-For IP Spoofing

**Timeline:** Before next minor release  
**Effort:** ~3 hours  
**Files to change:** `sanctum/guard.go`, `sanctum/config.go`, `sanctum/middleware.go`

### Task 2.1 — Add `TrustedProxyCIDRs` to `Config`

In `sanctum/config.go`, add:

```go
type Config struct {
    // ... existing fields ...

    // TrustedProxyCIDRs is the list of CIDR ranges for trusted reverse proxies.
    // When non-empty, X-Forwarded-For is only trusted for requests arriving from
    // these ranges. All other requests use RemoteAddr as the client IP.
    // Example: []string{"10.0.0.0/8", "172.16.0.0/12"}
    TrustedProxyCIDRs []string
}
```

### Task 2.2 — Parse CIDRs at `NewGuard` time

Parse `Config.TrustedProxyCIDRs` into `[]*net.IPNet` inside `NewGuard` so that runtime IP extraction does no allocation.

### Task 2.3 — Rewrite `extractIPAddress`

Replace the current implementation with one that:
1. Only consults `X-Forwarded-For` if `RemoteAddr` is within a trusted proxy CIDR.
2. When reading XFF, walks from rightmost to leftmost, returning the first IP that is NOT in a trusted proxy range (this is the true client IP per RFC 7239 §5.3).
3. Falls back to `RemoteAddr` when no trusted proxies are configured.

```go
func extractIPAddress(r *http.Request, trustedNets []*net.IPNet) *string {
    remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
    if len(trustedNets) > 0 && isTrustedProxy(net.ParseIP(remoteIP), trustedNets) {
        xff := r.Header.Get("X-Forwarded-For")
        for _, part := range reverseCSV(xff) {
            ip := net.ParseIP(strings.TrimSpace(part))
            if ip != nil && !isTrustedProxy(ip, trustedNets) {
                s := ip.String()
                return &s
            }
        }
    }
    return &remoteIP
}
```

### Task 2.4 — Update godoc

Add a prominent warning to `WithTokenValidator` and `Token.UserIP` that the IP value is only trustworthy when `Config.TrustedProxyCIDRs` is configured. Without it, `token.UserIP` must not be used for access control decisions.

### Task 2.5 — Tests

- Test that without `TrustedProxyCIDRs`, XFF header is ignored and `RemoteAddr` is used.
- Test that with `TrustedProxyCIDRs`, a request from a trusted proxy correctly resolves the client IP from XFF.
- Test that a spoofed XFF from a non-trusted remote address is ignored.

---

## Tracking Table

| ID | Severity | File | Task | Status |
|----|----------|------|------|--------|
| AUD-1 | HIGH | `passport/models.go` | Add `Audience` to `OAuthClient` | ☐ Open |
| AUD-2 | HIGH | `passport/adapter.go` | Implement `GetAudience()` | ☐ Open |
| AUD-3 | HIGH | `passport/resource.go` | Add `WithAudience` option | ☐ Open |
| AUD-4 | HIGH | `passport/resource.go` | Validate `aud` in `mapToClaims` | ☐ Open |
| AUD-5 | HIGH | `passport/errors.go` | Add `ErrAudienceMismatch` | ☐ Open |
| AUD-6 | HIGH | `passport/*_test.go` | Audience validation tests | ☐ Open |
| XFF-1 | MEDIUM | `sanctum/config.go` | Add `TrustedProxyCIDRs` field | ☐ Open |
| XFF-2 | MEDIUM | `sanctum/guard.go` | Parse CIDRs at `NewGuard` | ☐ Open |
| XFF-3 | MEDIUM | `sanctum/guard.go` | Rewrite `extractIPAddress` | ☐ Open |
| XFF-4 | MEDIUM | `sanctum/guard.go` | Update godoc warnings | ☐ Open |
| XFF-5 | MEDIUM | `sanctum/*_test.go` | Trusted proxy tests | ☐ Open |
