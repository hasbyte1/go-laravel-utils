# Security Audit: OAuth2/Passport Package — Full Codebase Review

**Date:** 2026-05-06  
**Auditor:** Claude Code (claude-sonnet-4-6)  
**Scope:** Full codebase — `passport/`, `sanctum/`, `encryption/`, `hashing/`  
**Method:** Complete static analysis of all Go source files  
**Previous audit:** `docs/security-audit-2026-05-06.md`

---

## Status of Previous Audit Findings

All four findings from the previous audit (2026-05-06) have been resolved in the current codebase:

| Finding | Status |
|---------|--------|
| HIGH — Timing oracle: token secret comparison (`sanctum/service.go:154`) | ✅ Fixed — now uses `crypto/subtle.ConstantTimeCompare` |
| HIGH — Timing oracle: OTP hash comparison (`sanctum/service.go:300`) | ✅ Fixed — now uses `crypto/subtle.ConstantTimeCompare` |
| MEDIUM — UserInfo endpoint ignores granted scopes (`passport/oidc.go:35`) | ✅ Fixed — now passes `ar.GetGrantedScopes()` and checks for `openid` scope |
| MEDIUM — RSA exponent truncation in JWK parsing (`passport/resource.go:264`) | ✅ Fixed — bounds check added; rejects exponents ≤ 1 or > 2³¹−1 |
| BUG — Fallback OTP comparison wrong operand (`sanctum/service.go:305`) | ✅ Fixed — now compares `fallbackHash` against `token.OTPHash` |

---

## Executive Summary

| Severity | Count |
|----------|-------|
| HIGH     | 1     |
| MEDIUM   | 1     |

The `encryption/` and `hashing/` packages remain well-hardened. The `sanctum/` timing oracles from the previous audit are resolved. Two new findings are documented below: a missing JWT audience claim validation that creates cross-service token confusion in multi-service deployments, and an X-Forwarded-For header spoofing vulnerability that undermines the advertised IP-based TokenValidator security feature.

---

## Vulnerability 1 — Missing JWT Audience Claim Validation

- **Severity:** HIGH
- **Confidence:** 0.90
- **Files:** `passport/resource.go:284–325`, `passport/adapter.go:471`
- **Category:** `authentication_bypass / cross_service_token_confusion`

### Description

The `ResourceGuard.validateJWT` flow calls `mapToClaims`, which validates only the `iss` (issuer) and `exp` (expiry) claims. The `aud` (audience) claim is never extracted or checked:

```go
// passport/resource.go:284
func mapToClaims(payload map[string]any, expectedIssuer string) (*TokenClaims, error) {
    iss, _ := payload["iss"].(string)
    if iss != expectedIssuer {
        return nil, fmt.Errorf("%w: issuer %q does not match expected %q", ErrInvalidToken, iss, expectedIssuer)
    }
    expF, hasExp := payload["exp"].(float64)
    // ... exp validated ...
    // aud is never extracted or validated
```

Compounding this, `fositeClient.GetAudience()` returns an empty slice, so tokens are issued without an `aud` claim at all:

```go
// passport/adapter.go:471
func (fc *fositeClient) GetAudience() fosite.Arguments { return fosite.Arguments{} }
```

Both sides of the audience contract are broken: tokens are minted with no audience restriction and the validator accepts any issuer-matched token regardless of audience.

### Exploit Scenario

In a multi-service deployment (the primary use case for a central OAuth2 authorization server):

1. Auth server issues a JWT access token for service A (payments API). Token contains `iss: "https://auth.example.com"`, no `aud` claim.
2. Attacker presents this token to service B's `ResourceGuard` (admin API), which also uses `issuer: "https://auth.example.com"`.
3. `ResourceGuard.validateJWT` accepts the token: signature valid, `iss` matches, `exp` not reached.
4. Attacker gains access to the admin API with a payments-scoped token.

Note: if the token carries narrow scopes (`aud: payments` only), scope-based checks in the application may limit impact. However, if the attacker's token has broad scopes (e.g., `*`), this is a full authentication bypass for any service sharing the issuer.

### Fix

**Step 1** — Emit `aud` in issued tokens. Override `GetAudience()` to return the intended audience for each client, or add a server-level audience configuration:

```go
// In fositeClient (adapter.go):
func (fc *fositeClient) GetAudience() fosite.Arguments {
    if len(fc.c.Audience) > 0 {
        return fc.c.Audience
    }
    return fosite.Arguments{}
}

// Add Audience field to OAuthClient (models.go):
type OAuthClient struct {
    // ...
    Audience []string  // e.g. ["https://api.example.com"]
}
```

**Step 2** — Add audience validation to `ResourceGuard`. Add a `WithAudience(audience string)` constructor option and validate `aud` in `mapToClaims`:

```go
type ResourceGuard struct {
    // ...
    audience string // expected audience; empty means no validation (backward compat)
}

func WithAudience(aud string) ResourceGuardOption {
    return func(g *ResourceGuard) { g.audience = aud }
}

// In mapToClaims:
if g.audience != "" {
    switch audClaim := payload["aud"].(type) {
    case string:
        if audClaim != g.audience {
            return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
        }
    case []any:
        found := false
        for _, v := range audClaim {
            if s, ok := v.(string); ok && s == g.audience {
                found = true
                break
            }
        }
        if !found {
            return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
        }
    default:
        return nil, fmt.Errorf("%w: missing or invalid aud claim", ErrInvalidToken)
    }
}
```

**RFC reference:** RFC 9068 §4 requires `aud` claim to be present and validated in JWT Access Tokens. RFC 7519 §4.1.3 requires rejection when the recipient identifies itself and is not listed in `aud`.

---

## Vulnerability 2 — X-Forwarded-For Header Spoofing Undermines IP Allowlisting

- **Severity:** MEDIUM
- **Confidence:** 0.82
- **File:** `sanctum/guard.go:246–270`
- **Category:** `authentication_bypass / ip_spoofing`

### Description

`extractIPAddress` unconditionally trusts the `X-Forwarded-For` (XFF) header, extracting the leftmost (client-supplied) IP without verifying the request passed through a trusted proxy:

```go
// sanctum/guard.go:248
if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
    if idx := strings.Index(xff, ","); idx > 0 {
        return ptrString(strings.TrimSpace(xff[:idx]))
    }
    return ptrString(strings.TrimSpace(xff))
}
```

The leftmost IP in `X-Forwarded-For` is the one appended by the client itself — it is entirely attacker-controlled. The comment on line 248 incorrectly states the list is "in reverse order"; RFC 7239 appends the client IP first (leftmost) and each successive proxy appends itself after. Extracting `xff[:idx]` (the leftmost entry) returns the client-controlled IP.

This matters because the public API explicitly documents IP-based allowlisting as a first-class security feature of `TokenValidator`:

```go
// sanctum/guard.go:9
// TokenValidator is a hook invoked after a Bearer token is successfully authenticated.
// Typical uses: IP allow-listing, device fingerprinting, rate limiting.
```

The IP value extracted by `extractIPAddress` is also persisted to `Token.UserIP` via `UpdateLastUsedAtAndUserIP`, so stored IP records are equally unreliable.

### Exploit Scenario

1. Consumer configures a `TokenValidator` for IP allowlisting: only tokens from `10.0.0.5` (an internal service) are accepted.
2. Attacker holds a valid bearer token (e.g., obtained via phishing) from an external IP.
3. Attacker sends: `curl -H "X-Forwarded-For: 10.0.0.5" -H "Authorization: Bearer <token>" https://api.example.com/secure`
4. `extractIPAddress` returns `"10.0.0.5"`.
5. `TokenValidator` passes the IP check → authentication succeeds → bypass.

### Fix

Add a `WithTrustedProxyCIDRs` guard option. When set, strip the XFF list to the leftmost IP not appended by a trusted proxy. When not set, fall back to `r.RemoteAddr` only and document clearly that the IP is untrusted:

```go
// GuardOption
func WithTrustedProxyCIDRs(cidrs []string) GuardOption {
    nets := make([]*net.IPNet, 0, len(cidrs))
    for _, c := range cidrs {
        _, ipNet, err := net.ParseCIDR(c)
        if err == nil {
            nets = append(nets, ipNet)
        }
    }
    return func(g *Guard) { g.trustedProxyCIDRs = nets }
}

func extractIPAddress(r *http.Request, trustedNets []*net.IPNet) *string {
    if len(trustedNets) > 0 {
        remoteIP := net.ParseIP(stripPort(r.RemoteAddr))
        if remoteIP != nil && isTrusted(remoteIP, trustedNets) {
            // Only trust XFF if the direct connection is from a trusted proxy.
            if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
                ips := strings.Split(xff, ",")
                // Return the rightmost IP not in the trusted range (the true client).
                for i := len(ips) - 1; i >= 0; i-- {
                    ip := net.ParseIP(strings.TrimSpace(ips[i]))
                    if ip != nil && !isTrusted(ip, trustedNets) {
                        return ptrString(ip.String())
                    }
                }
            }
        }
    }
    // No trusted proxies configured or direct connection: use RemoteAddr.
    return ptrString(stripPort(r.RemoteAddr))
}
```

Until the fix is applied, document clearly that `token.UserIP` must not be used for security decisions without trusted-proxy configuration.

---

## Confirmed-Secure Areas (current codebase)

| Package | Control | Verdict |
|---------|---------|---------|
| `encryption/` | MAC verified before decryption (padding oracle prevention) | ✅ Correct |
| `encryption/` | `crypto/subtle.ConstantTimeCompare` for HMAC | ✅ Correct |
| `encryption/` | Fresh `crypto/rand` IV/nonce on every encrypt call | ✅ Correct |
| `encryption/` | Keys deep-copied on ingestion | ✅ Correct |
| `hashing/` | Bcrypt cost 12 (≥ OWASP ASVS L2) | ✅ Correct |
| `hashing/` | Argon2 m=64MiB t=3 p=2 (≥ RFC 9106 recommendation) | ✅ Correct |
| `hashing/` | `crypto/subtle` for hash comparison | ✅ Correct |
| `sanctum/csrf.go` | `crypto/subtle` for CSRF token comparison | ✅ Correct |
| `sanctum/service.go:155` | `crypto/subtle.ConstantTimeCompare` for token secret | ✅ Fixed in this release |
| `sanctum/service.go:298` | `crypto/subtle.ConstantTimeCompare` for OTP comparison | ✅ Fixed in this release |
| `sanctum/service.go:302` | Fallback OTP compared against `token.OTPHash` | ✅ Fixed in this release |
| `passport/server.go` | `EnablePKCEPlainChallengeMethod: false` | ✅ Correct |
| `passport/server.go` | `EnforcePKCEForPublicClients: true` | ✅ Correct |
| `passport/server.go` | `SendDebugMessagesToClients: false` | ✅ Correct |
| `passport/resource.go` | `alg: RS256` enforced before signature verification | ✅ Correct |
| `passport/resource.go:264` | RSA exponent bounds validated (1 < e ≤ 2³¹−1) | ✅ Fixed in this release |
| `passport/adapter.go` | Refresh token rotation via `RevokeRefreshTokensByRequestID` | ✅ Correct |
| `passport/oidc.go` | UserInfo checks `openid` scope, passes granted scopes to provider | ✅ Fixed in this release |
| `arr/`, `collections/` | No unsafe operations or injection vectors | ✅ Correct |
