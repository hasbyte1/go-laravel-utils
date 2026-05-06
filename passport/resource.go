package passport

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type contextKey int

const claimsKey contextKey = iota

// TokenClaims holds the validated claims from a JWT access token.
type TokenClaims struct {
	Subject   string
	ClientID  string
	Scopes    []string
	Issuer    string
	ExpiresAt time.Time
	Extra     map[string]any
}

// HasScope reports whether every requested scope is present in the claims.
func (c *TokenClaims) HasScope(scopes ...string) bool {
	set := make(map[string]struct{}, len(c.Scopes))
	for _, s := range c.Scopes {
		set[s] = struct{}{}
	}
	for _, s := range scopes {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// ClaimsFromContext retrieves the *TokenClaims stored by ResourceGuard.Middleware.
// Returns nil when no claims are present.
func ClaimsFromContext(ctx context.Context) *TokenClaims {
	v, _ := ctx.Value(claimsKey).(*TokenClaims)
	return v
}

// ResourceGuardOption is a functional option for ResourceGuard.
type ResourceGuardOption func(*ResourceGuard)

// WithHTTPClient sets a custom HTTP client for remote JWKS fetching.
func WithHTTPClient(client *http.Client) ResourceGuardOption {
	return func(g *ResourceGuard) { g.httpClient = client }
}

// WithCacheTTL sets how long the JWKS response is cached (default 1 hour).
func WithCacheTTL(d time.Duration) ResourceGuardOption {
	return func(g *ResourceGuard) { g.cacheTTL = d }
}

// ResourceGuard validates JWT access tokens issued by a passport Server.
type ResourceGuard struct {
	issuer     string
	staticKey  crypto.PublicKey // non-nil for static-key mode
	jwksURL    string           // non-empty for remote-JWKS mode
	httpClient *http.Client
	cacheTTL   time.Duration

	mu          sync.RWMutex
	cachedKeys  map[string]crypto.PublicKey // kid → public key
	cacheExpiry time.Time
	sf          singleflight.Group // deduplicates concurrent JWKS refreshes
}

// NewResourceGuard validates tokens using a static public key.
// Use when the resource server and auth server share the same process or the key
// is loaded from disk at startup.
func NewResourceGuard(issuer string, key crypto.PublicKey) *ResourceGuard {
	return &ResourceGuard{
		issuer:    issuer,
		staticKey: key,
		cacheTTL:  time.Hour,
	}
}

// NewRemoteResourceGuard fetches and caches the JWKS from jwksURL.
// The cache is refreshed on expiry or on encountering an unknown key ID.
func NewRemoteResourceGuard(issuer, jwksURL string, opts ...ResourceGuardOption) *ResourceGuard {
	g := &ResourceGuard{
		issuer:     issuer,
		jwksURL:    jwksURL,
		httpClient: http.DefaultClient,
		cacheTTL:   time.Hour,
		cachedKeys: make(map[string]crypto.PublicKey),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Authenticate validates the Bearer token in r and returns its claims.
// Returns ErrUnauthorized, ErrTokenExpired, or ErrInvalidToken on failure.
func (g *ResourceGuard) Authenticate(r *http.Request) (*TokenClaims, error) {
	token := extractBearer(r)
	if token == "" {
		return nil, ErrUnauthorized
	}
	return g.validateJWT(r.Context(), token)
}

// Middleware is a standard net/http middleware that validates the Bearer token.
// On success it stores *TokenClaims in the request context (retrieve with ClaimsFromContext).
// On failure it writes a 401 JSON response.
func (g *ResourceGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := g.Authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`)) //nolint:errcheck
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

func (g *ResourceGuard) validateJWT(ctx context.Context, token string) (*TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidToken
	}
	if header.Alg != "RS256" {
		return nil, ErrInvalidToken
	}

	key, err := g.resolveKey(ctx, header.Kid)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if err := verifyRS256(parts[0]+"."+parts[1], parts[2], key); err != nil {
		return nil, ErrInvalidToken
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, ErrInvalidToken
	}

	return mapToClaims(payload, g.issuer)
}

func (g *ResourceGuard) resolveKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if g.staticKey != nil {
		return g.staticKey, nil
	}
	g.mu.RLock()
	key, ok := g.cachedKeys[kid]
	expired := time.Now().After(g.cacheExpiry)
	g.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}
	// Deduplicate concurrent refreshes so only one HTTP request is in flight.
	_, err, _ := g.sf.Do("jwks", func() (any, error) {
		return nil, g.refreshJWKS(ctx)
	})
	if err != nil {
		return nil, err
	}
	g.mu.RLock()
	key, ok = g.cachedKeys[kid]
	g.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("passport: unknown key id %q", kid)
	}
	return key, nil
}

func (g *ResourceGuard) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("passport: JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}
	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSA(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	g.mu.Lock()
	g.cachedKeys = keys
	g.cacheExpiry = time.Now().Add(g.cacheTTL)
	g.mu.Unlock()
	return nil
}

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

func verifyRS256(signingInput, sig string, key crypto.PublicKey) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("passport: unsupported key type")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sigBytes)
}

func mapToClaims(payload map[string]any, expectedIssuer string) (*TokenClaims, error) {
	iss, _ := payload["iss"].(string)
	if iss != expectedIssuer {
		return nil, fmt.Errorf("%w: issuer %q does not match expected %q", ErrInvalidToken, iss, expectedIssuer)
	}
	expF, hasExp := payload["exp"].(float64)
	if !hasExp {
		return nil, ErrInvalidToken
	}
	exp := time.Unix(int64(expF), 0)
	if time.Now().After(exp) {
		return nil, ErrTokenExpired
	}
	sub, _ := payload["sub"].(string)
	clientID, _ := payload["client_id"].(string)
	var scopes []string
	if s, ok := payload["scp"].(string); ok {
		scopes = strings.Split(s, " ")
	} else if arr, ok := payload["scp"].([]any); ok {
		for _, v := range arr {
			if sv, ok := v.(string); ok {
				scopes = append(scopes, sv)
			}
		}
	}
	extra := make(map[string]any)
	for k, v := range payload {
		switch k {
		case "sub", "iss", "exp", "iat", "client_id", "scp":
		default:
			extra[k] = v
		}
	}
	return &TokenClaims{
		Subject:   sub,
		ClientID:  clientID,
		Scopes:    scopes,
		Issuer:    iss,
		ExpiresAt: exp,
		Extra:     extra,
	}, nil
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return auth[7:]
	}
	return ""
}
