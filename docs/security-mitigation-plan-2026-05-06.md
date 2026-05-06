# Security Mitigation Plan

**Audit source:** `docs/security-audit-2026-05-06.md`  
**Created:** 2026-05-06

Ordered by impact × effort. All fixes are localised; none require API changes or dependency upgrades.

---

## Phase 1 — Immediate (1–2 hours, same PR)

These are mechanical one-line fixes with no API impact.

### Fix 1.1 — Constant-time token secret comparison

**File:** `sanctum/service.go:154`

```go
// Before
if HashToken(secret) != token.Hash {
    return nil, nil, ErrInvalidToken
}

// After
import "crypto/subtle"

if subtle.ConstantTimeCompare([]byte(HashToken(secret)), []byte(token.Hash)) != 1 {
    return nil, nil, ErrInvalidToken
}
```

**Test:** Existing `TestAuthenticateByID` — no changes needed; the behaviour is identical for correct inputs.

---

### Fix 1.2 — Constant-time OTP comparison + fix fallback logic bug

**File:** `sanctum/service.go:299–306`

```go
// Before
otpHash := HashOTP(providedOTP)
isValid := otpHash == token.OTPHash

if !isValid && fallbackOTP != nil {
    fallbackHash := HashOTP(*fallbackOTP)
    isValid = fallbackHash == otpHash
}

// After
otpHash := HashOTP(providedOTP)
isValid := subtle.ConstantTimeCompare([]byte(otpHash), []byte(token.OTPHash)) == 1

if !isValid && fallbackOTP != nil {
    fallbackHash := HashOTP(*fallbackOTP)
    isValid = subtle.ConstantTimeCompare([]byte(fallbackHash), []byte(token.OTPHash)) == 1
}
```

**Note:** The fallback comparison was comparing `fallbackHash` against `otpHash` (bug — always fails unless the user typed the fallback value). The fix compares both hashes against `token.OTPHash`. This is a **behavioural change** for the fallback path — the fallback OTP will now actually work.

**Test:** Add a test case where `providedOTP` is wrong but `fallbackOTP` is correct, and assert `isValid == true`.

---

### Fix 1.3 — Remove duplicate IsValidToken call

**File:** `sanctum/service.go:185–190`

Delete lines 188–190 (the second identical `IsValidToken` call).

---

## Phase 2 — Short-term (1 day)

### Fix 2.1 — Validate RSA exponent in JWK parsing

**File:** `passport/resource.go:253–265`

Add exponent bounds validation before constructing `rsa.PublicKey`:

```go
import (
    "errors"
    "math/big"
)

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

    maxE := big.NewInt(1<<31 - 1)
    if e.Cmp(big.NewInt(1)) <= 0 || e.Cmp(maxE) > 0 {
        return nil, errors.New("passport: JWK RSA exponent out of valid range")
    }
    return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
```

**Test:** Add a table-driven test with exponent values: `0`, `1`, `65537` (valid), `math.MaxInt32+1` (invalid), and a byte string decoding to a value > MaxInt64 (invalid).

---

### Fix 2.2 — Enforce scope at UserInfo endpoint

**File:** `passport/oidc.go:15–45`

Use `ar.GetGrantedScopes()` (returned by `IntrospectToken`) to pass actual scopes to `GetUserInfo`, and reject requests missing the `openid` scope:

```go
func (s *Server) HandleUserInfo() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        sess := newEmptySession()
        _, ar, err := s.provider.IntrospectToken(ctx, fosite.AccessTokenFromRequest(r), fosite.AccessToken, sess)
        if err != nil {
            http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
            return
        }

        grantedScopes := ar.GetGrantedScopes()
        if !grantedScopes.Has("openid") {
            http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
            return
        }

        userID := sess.Subject
        user, err := s.users.FindByID(ctx, userID)
        if err != nil || user == nil {
            http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
            return
        }

        claims, err := s.userInfo.GetUserInfo(ctx, user, grantedScopes)
        if err != nil {
            http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
            return
        }
        claims["sub"] = userID

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(claims) //nolint:errcheck
    })
}
```

**Note:** Verify that fosite v0.49's `IntrospectToken` returns a usable `AuthorizeRequest` (second return value) for JWT access tokens. If not, scope must be extracted from the JWT claims directly via `sess` (the `combinedSession` already carries scope in `ExtraClaims` if the enricher populates it).

**Test:** Assert that calling `/oauth/userinfo` with a token that lacks `openid` scope returns HTTP 403.

---

## Phase 3 — Cleanup (optional)

### Fix 3.1 — Collapse EphemeralKV.Get() under a single write lock

**Files:** `passport/inmemory/ephemeral.go:40–55`, `passport/adapter.go:363–378`

Replace the read-then-write pattern with a single exclusive lock. This eliminates the TOCTOU window and makes the code obviously correct:

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

Apply the same pattern to `adapter.go:internalEphKV.Get()`.

---

### Fix 3.2 — Strip debug details from authorization error responses

**File:** `passport/handlers.go:36, 48, 71`

Log errors server-side and pass a clean error to the fosite writer:

```go
// Before
s.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithDebug(err.Error()))

// After (wherever this pattern appears)
log.Printf("passport: authorize error: %v", err)
s.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError)
```

---

## Verification Checklist

After implementing Phase 1 and Phase 2 fixes, run:

```bash
go test -race ./sanctum/...
go test -race ./passport/...
go vet ./...
```

Confirm:
- [ ] All existing tests pass
- [ ] New OTP fallback test passes (Fix 1.2)
- [ ] New JWK exponent bounds test passes (Fix 2.1)
- [ ] New `/oauth/userinfo` scope test passes (Fix 2.2)
- [ ] No data races reported by `-race`

---

## Priority Summary

| ID   | Finding                                   | Severity | Phase | Effort |
|------|-------------------------------------------|----------|-------|--------|
| 1.1  | Token secret timing oracle                | HIGH     | 1     | 5 min  |
| 1.2  | OTP timing oracle + fallback logic bug    | HIGH     | 1     | 10 min |
| 1.3  | Duplicate IsValidToken call               | Bug      | 1     | 1 min  |
| 2.1  | RSA exponent truncation in JWK parsing    | MEDIUM   | 2     | 30 min |
| 2.2  | UserInfo endpoint ignores granted scopes  | MEDIUM   | 2     | 1 hr   |
| 3.1  | EphemeralKV TOCTOU window                 | LOW      | 3     | 20 min |
| 3.2  | Debug details in authorize error path     | LOW      | 3     | 10 min |
