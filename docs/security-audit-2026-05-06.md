# Security Audit: go-laravel-utils

**Date:** 2026-05-06  
**Auditor:** Claude Code (claude-sonnet-4-6)  
**Scope:** Full codebase — `passport/`, `sanctum/`, `encryption/`, `hashing/`, `arr/`, `collections/`  
**Method:** Static analysis of all Go source files

---

## Executive Summary

| Severity | Count |
|----------|-------|
| HIGH     | 2     |
| MEDIUM   | 2     |
| LOW      | 2     |
| Bug (non-security) | 1 |

The `encryption/` and `hashing/` packages are well-hardened (MAC-before-decrypt, `crypto/subtle` comparisons, strong defaults). The main vulnerabilities are concentrated in `sanctum/service.go` (timing oracles) and `passport/oidc.go` + `passport/resource.go` (scope enforcement and JWK parsing).

---

## Vulnerability 1 — Timing Oracle: Token Secret Comparison

- **Severity:** HIGH  
- **Confidence:** 0.95  
- **File:** `sanctum/service.go:154`  
- **Category:** `timing_oracle / authentication_bypass`

### Description

The token secret hash is compared using Go's native string inequality operator, which short-circuits on the first differing byte:

```go
if HashToken(secret) != token.Hash {
    return nil, nil, ErrInvalidToken
}
```

This leaks timing information proportional to the length of the common prefix between the attacker-supplied hash and the stored hash.

### Exploit Scenario

An attacker with a high-volume token endpoint (e.g., a shared SaaS deployment) can mount a remote timing attack:

1. For each hex character position (0–63), enumerate all 16 possible hex digits.
2. Measure the average response latency for each candidate across hundreds of requests.
3. The candidate producing the highest latency has the longest matching prefix.
4. Repeat for each position to recover the full 64-character SHA-256 hex digest.
5. Construct a token string `<known-uuid>|<brute-forced-secret>` where `sha256(secret)` equals the recovered hash.

In practice this requires low network jitter and many requests, but it is a documented class of vulnerability against authentication systems.

### Fix

```go
import "crypto/subtle"

if subtle.ConstantTimeCompare([]byte(HashToken(secret)), []byte(token.Hash)) != 1 {
    return nil, nil, ErrInvalidToken
}
```

---

## Vulnerability 2 — Timing Oracle: OTP Hash Comparison

- **Severity:** HIGH  
- **Confidence:** 0.95  
- **File:** `sanctum/service.go:300`  
- **Category:** `timing_oracle / authentication_bypass`

### Description

Both the primary and fallback OTP hash comparisons use `==`:

```go
otpHash := HashOTP(providedOTP)
isValid := otpHash == token.OTPHash          // line 300 — not constant-time

if !isValid && fallbackOTP != nil {
    fallbackHash := HashOTP(*fallbackOTP)
    isValid = fallbackHash == otpHash         // line 305 — not constant-time
}
```

This is the same timing-oracle class as Vulnerability 1.

### Exploit Scenario

An attacker can brute-force the stored OTP hash character by character using timing measurements, then forge a valid OTP input that produces that hash. Because OTP secrets are typically short-lived and rate-limited (see also Bug 1 below), this is harder to exploit than Vuln 1, but the pattern is dangerous and should be fixed to match the `encryption/` package's own standards.

### Fix

```go
import "crypto/subtle"

otpHash := HashOTP(providedOTP)
isValid := subtle.ConstantTimeCompare([]byte(otpHash), []byte(token.OTPHash)) == 1

if !isValid && fallbackOTP != nil {
    fallbackHash := HashOTP(*fallbackOTP)
    isValid = subtle.ConstantTimeCompare([]byte(fallbackHash), []byte(token.OTPHash)) == 1
}
```

---

## Vulnerability 3 — UserInfo Endpoint Ignores Granted Scopes

- **Severity:** MEDIUM  
- **Confidence:** 0.90  
- **File:** `passport/oidc.go:35`  
- **Category:** `authorization_bypass / data_exposure`

### Description

The `/oauth/userinfo` endpoint authenticates the bearer token but then calls `GetUserInfo` with an empty scope list, regardless of what scopes were actually granted to the token:

```go
// IntrospectToken does not expose granted scopes through DefaultSession;
// pass empty scopes — the UserInfoProvider may look them up itself.
claims, err := s.userInfo.GetUserInfo(ctx, user, []string{})
```

The comment acknowledges the problem but delegates scope enforcement entirely to the `UserInfoProvider` implementation. Any `UserInfoProvider` that does not re-query the database for granted scopes will return full claims to any valid access token.

### Exploit Scenario

1. Attacker registers a client and obtains an access token with only the `read:orders` scope (no `openid` or `profile`).
2. Attacker calls `GET /oauth/userinfo` with that token.
3. Because scope list passed to `GetUserInfo` is empty, the provider returns all claims — email, name, profile data — even though the token never requested them.
4. Attacker receives PII it was not authorized for.

### Fix

Use `fosite.IntrospectToken` with a session type that exposes the granted scope list, or use a `combinedSession` (already defined in `adapter.go`) which embeds `openid.DefaultSession` and can carry scopes:

```go
sess := newEmptySession()  // combinedSession, not openid.DefaultSession
tokenType, ar, err := s.provider.IntrospectToken(ctx, fosite.AccessTokenFromRequest(r), fosite.AccessToken, sess)
if err != nil { ... }

grantedScopes := ar.GetGrantedScopes()
claims, err := s.userInfo.GetUserInfo(ctx, user, grantedScopes)
```

At minimum, validate that `openid` is in the granted scope before returning any claims:

```go
if !ar.GetGrantedScopes().Has("openid") {
    http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
    return
}
```

---

## Vulnerability 4 — RSA Exponent Truncation in JWK Parsing

- **Severity:** MEDIUM  
- **Confidence:** 0.85  
- **File:** `passport/resource.go:264`  
- **Category:** `crypto / signature_forgery`

### Description

`jwkToRSA` converts the base64url-encoded `e` parameter of a JWK into an `int` without bounds checking:

```go
n := new(big.Int).SetBytes(nBytes)
e := new(big.Int).SetBytes(eBytes)
return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
```

`big.Int.Int64()` silently wraps values outside the signed 64-bit range, and `int(...)` wraps again on 32-bit platforms. An exponent larger than `math.MaxInt64` produces a garbage or negative value. Go's `rsa.VerifyPKCS1v15` returns an error for exponents ≤ 0, but does not validate against a specific whitelist, so a crafted exponent could produce unexpected behaviour in edge cases.

### Exploit Scenario

Applies when `ResourceGuard` is configured with a remote JWKS URL (`WithRemoteJWKS`):

1. Attacker performs a MITM or DNS poisoning attack against the JWKS endpoint.
2. Serves a JWKS with an exponent field whose decoded byte value exceeds `math.MaxInt64`.
3. The parsed `rsa.PublicKey.E` becomes 0 or negative.
4. Signature verification fails or behaves unexpectedly, potentially accepting tokens signed with an attacker-controlled key.

This requires network-level access to the JWKS endpoint, making it a medium rather than high severity issue.

### Fix

```go
func jwkToRSA(nB64, eB64 string) (*rsa.PublicKey, error) {
    nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
    if err != nil {
        return nil, err
    }
    eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
    if err != nil {
        return nil, err
    }
    n := new(big.Int).SetBytes(nBytes)
    e := new(big.Int).SetBytes(eBytes)

    // Reject non-standard exponents; standard RSA public exponents are 3, 17, or 65537.
    // Accept anything in the valid 32-bit range but reject ≤ 1 and > 2^31-1.
    maxE := big.NewInt(1<<31 - 1)
    if e.Cmp(big.NewInt(1)) <= 0 || e.Cmp(maxE) > 0 {
        return nil, errors.New("passport: JWK RSA exponent out of valid range")
    }
    return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
```

---

## Low Severity Findings

### L1 — TOCTOU Window in EphemeralKV.Get()

- **Severity:** LOW  
- **Files:** `passport/inmemory/ephemeral.go:40–55`, `passport/adapter.go:363–378`

Both in-memory `EphemeralKV` implementations release the read lock before performing the expiry check against the locally-copied entry. Between the read lock release and the time comparison, a concurrent goroutine can set or delete the same key. Because `entry` is a struct value (not a pointer), the expiry check operates on the value captured at read time, so the window cannot cause an expired entry to appear valid to the goroutine that read it. In practice the race only causes a redundant `delete()` call, which is a no-op in Go. The risk of a genuinely expired key being served is limited to sub-millisecond clock granularity at the exact TTL boundary — negligible for authorization code lifespans of 60+ seconds.

**Recommendation:** Consolidate the expiry check inside the write lock to eliminate any ambiguity and make the code obviously correct:

```go
func (e *ephemeralKV) Get(_ context.Context, key string) ([]byte, error) {
    e.mu.Lock()
    defer e.mu.Unlock()
    entry, ok := e.entries[key]
    if !ok {
        return nil, passport.ErrKeyNotFound
    }
    if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
        delete(e.entries, key)
        return nil, passport.ErrKeyNotFound
    }
    v := make([]byte, len(entry.value))
    copy(v, entry.value)
    return v, nil
}
```

This does increase lock contention, but `Get` is a trivial in-memory map read — the impact is negligible.

### L2 — Internal Error Details Attached to Authorize Error Responses

- **Severity:** LOW  
- **Files:** `passport/handlers.go:36, 48, 71`

Several error paths call `fosite.ErrServerError.WithDebug(err.Error())`. The fosite config sets `SendDebugMessagesToClients: false`, which should suppress the debug string in OAuth responses. However, if that config value is ever changed (e.g., during development) or a future fosite version changes the behaviour, internal error messages from `UserSessionProvider`, `ConsentProvider`, and the token enricher would leak to clients. Prefer logging the internal error server-side and passing a plain `fosite.ErrServerError` to the writer:

```go
// Instead of:
s.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithDebug(err.Error()))

// Prefer:
log.Printf("passport: session provider error: %v", err)
s.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError)
```

---

## Non-Security Bug

### B1 — Fallback OTP Comparison is Broken (Logic Error)

- **File:** `sanctum/service.go:305`  
- **Type:** Logic bug (not a security vulnerability — makes the check stricter, not weaker)

The fallback OTP check compares the hash of the fallback value against the hash of the *provided* OTP, not against the stored token hash:

```go
fallbackHash := HashOTP(*fallbackOTP)
isValid = fallbackHash == otpHash   // BUG: should be == token.OTPHash
```

This means the fallback check can only succeed if `fallbackOTP == providedOTP`, which defeats its purpose (supporting TOTP window tolerance). The fix:

```go
isValid = subtle.ConstantTimeCompare([]byte(fallbackHash), []byte(token.OTPHash)) == 1
```

---

## Duplicate Validation Call (Code Quality)

- **File:** `sanctum/service.go:185–189`

`IsValidToken` is called twice consecutively with identical arguments:

```go
if err := s.IsValidToken(token, checkOTPFlag, false); err != nil { return nil, nil, err }
if err := s.IsValidToken(token, checkOTPFlag, false); err != nil { return nil, nil, err }  // duplicate
```

Remove the second call.

---

## Confirmed-Secure Areas

| Package | Control | Verdict |
|---------|---------|---------|
| `encryption/` | MAC verified before decryption (padding oracle prevention) | ✓ Correct |
| `encryption/` | `crypto/subtle.ConstantTimeCompare` for HMAC | ✓ Correct |
| `encryption/` | Fresh `crypto/rand` IV on every encrypt call | ✓ Correct |
| `encryption/` | Keys deep-copied on ingestion | ✓ Correct |
| `hashing/` | Bcrypt cost 12 (≥ OWASP ASVS L2) | ✓ Correct |
| `hashing/` | Argon2 m=64MiB t=3 p=2 (≥ OWASP ASVS L2) | ✓ Correct |
| `hashing/` | `crypto/subtle` for hash comparison | ✓ Correct |
| `sanctum/csrf.go` | `crypto/subtle` for CSRF token comparison | ✓ Correct |
| `passport/server.go` | `EnablePKCEPlainChallengeMethod: false` | ✓ Correct |
| `passport/server.go` | `EnforcePKCEForPublicClients: true` | ✓ Correct |
| `passport/server.go` | `SendDebugMessagesToClients: false` | ✓ Correct |
| `passport/resource.go` | `alg: RS256` enforced on token header before verification | ✓ Correct |
| `passport/resource.go` | `kid` looked up after JWKS refresh; unknown KID returns error | ✓ Correct |
| `passport/adapter.go` | Refresh token rotation via `RevokeRefreshTokensByRequestID` | ✓ Correct |
| `arr/`, `collections/` | No unsafe operations or injection vectors | ✓ Correct |
