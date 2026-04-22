package passport_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hasbyte1/go-laravel-utils/passport"
)

func makeTestJWT(t *testing.T, key *rsa.PrivateKey, issuer, subject string, exp time.Time, scopes []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"default","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": subject,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
		"scp": strings.Join(scopes, " "),
	})
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sigInput := header + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestResourceGuard_Authenticate_valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	guard := passport.NewResourceGuard("https://auth.example.com", &key.PublicKey)

	token := makeTestJWT(t, key, "https://auth.example.com", "user-1",
		time.Now().Add(time.Hour), []string{"read", "write"})

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	claims, err := guard.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("wrong subject: %s", claims.Subject)
	}
	if !claims.HasScope("read") {
		t.Fatal("expected read scope")
	}
}

func TestResourceGuard_Authenticate_expired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	guard := passport.NewResourceGuard("https://auth.example.com", &key.PublicKey)

	token := makeTestJWT(t, key, "https://auth.example.com", "user-1",
		time.Now().Add(-time.Hour), []string{"read"})

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	_, err := guard.Authenticate(r)
	if err != passport.ErrTokenExpired {
		t.Fatalf("got %v, want ErrTokenExpired", err)
	}
}

func TestResourceGuard_Authenticate_wrongIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	guard := passport.NewResourceGuard("https://auth.example.com", &key.PublicKey)

	token := makeTestJWT(t, key, "https://wrong.example.com", "user-1",
		time.Now().Add(time.Hour), []string{"read"})

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	_, err := guard.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestResourceGuard_Middleware_setsContext(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	guard := passport.NewResourceGuard("https://auth.example.com", &key.PublicKey)

	token := makeTestJWT(t, key, "https://auth.example.com", "user-42",
		time.Now().Add(time.Hour), []string{"profile"})

	var gotClaims *passport.TokenClaims
	handler := guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = passport.ClaimsFromContext(r.Context())
	}))

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(w, r)

	if gotClaims == nil {
		t.Fatal("claims not in context")
	}
	if gotClaims.Subject != "user-42" {
		t.Fatalf("wrong subject: %s", gotClaims.Subject)
	}
}

func TestResourceGuard_Middleware_unauthorized(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	guard := passport.NewResourceGuard("https://auth.example.com", &key.PublicKey)

	called := false
	handler := guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if called {
		t.Fatal("next handler should not be called on missing token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want 401", w.Code)
	}
}

func TestNewRemoteResourceGuard_refreshesJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{map[string]any{"kty": "RSA", "kid": "default", "n": n, "e": e}},
		})
	}))
	defer jwkServer.Close()

	guard := passport.NewRemoteResourceGuard("https://auth.example.com", jwkServer.URL)

	token := makeTestJWT(t, key, "https://auth.example.com", "user-remote",
		time.Now().Add(time.Hour), []string{"read"})

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	claims, err := guard.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-remote" {
		t.Fatalf("wrong subject: %s", claims.Subject)
	}
}

// Verify context is preserved — ClaimsFromContext returns nil when no claims stored.
func TestClaimsFromContext_nil(t *testing.T) {
	claims := passport.ClaimsFromContext(context.Background())
	if claims != nil {
		t.Fatal("expected nil claims from empty context")
	}
}
