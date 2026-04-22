package passport_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/passport"
	"github.com/hasbyte1/go-laravel-utils/passport/inmemory"
	"github.com/hasbyte1/go-laravel-utils/sanctum"
)

// testUser satisfies sanctum.User.
type testUser struct{ id string }

func (u *testUser) GetID() string { return u.id }

// testUserProvider satisfies sanctum.UserProvider.
type testUserProvider struct{ u sanctum.User }

func (p *testUserProvider) FindByID(_ context.Context, id string) (sanctum.User, error) {
	if p.u.GetID() == id {
		return p.u, nil
	}
	return nil, nil
}

// testUserInfoProvider returns minimal OIDC claims.
type testUserInfoProvider struct{}

func (p *testUserInfoProvider) GetUserInfo(_ context.Context, user sanctum.User, scopes []string) (map[string]any, error) {
	return map[string]any{"name": "Test User", "email": "test@example.com"}, nil
}

func setupServer(t *testing.T) (*passport.Server, *inmemory.Store, *inmemory.SessionStore, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	store := inmemory.New()
	store.AddClient(&passport.OAuthClient{
		ID:           "test-client",
		SecretHash:   "$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO", // = "foobar"
		Name:         "Test Client",
		RedirectURIs: []string{"http://localhost/callback"},
		GrantTypes:   []string{"authorization_code", "client_credentials", "refresh_token"},
		Scopes:       []string{"openid", "profile", "read"},
		Public:       false,
	})
	store.AddClient(&passport.OAuthClient{
		ID:           "public-client",
		Name:         "Public Client",
		RedirectURIs: []string{"http://localhost/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile"},
		Public:       true,
	})

	user := &testUser{id: "user-1"}
	sessions := inmemory.NewSessionStore()
	sessions.Set("valid-session", user)

	cfg := passport.DefaultConfig("http://127.0.0.1")
	cfg.GlobalSecret = []byte("01234567890123456789012345678901") // 32 bytes
	cfg.LoginURL = "http://localhost/login"
	cfg.ConsentURL = "http://localhost/consent"

	srv, err := passport.NewServer(
		cfg, store, store, store, store, store,
		sessions, inmemory.NewConsentStore(), &testUserInfoProvider{},
		&testUserProvider{u: user}, key,
	)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	return srv, store, sessions, ts
}

func TestServer_ClientCredentials(t *testing.T) {
	_, _, _, ts := setupServer(t)
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"foobar"},
		"scope":         {"read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["access_token"] == "" {
		t.Fatal("no access_token in response")
	}
	if result["token_type"] != "bearer" {
		t.Fatalf("unexpected token_type: %v", result["token_type"])
	}
}

func TestServer_AuthorizeRedirectsToLoginWhenNoSession(t *testing.T) {
	_, _, _, ts := setupServer(t)
	defer ts.Close()

	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	// state must be at least 8 characters long to satisfy fosite entropy requirements.
	resp, err := client.Get(ts.URL + "/oauth/authorize?response_type=code&client_id=public-client&redirect_uri=http://localhost/callback&scope=openid&state=xyzxyzxy&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "login") {
		t.Fatalf("expected redirect to login, got %q", loc)
	}
}

func TestServer_Discovery(t *testing.T) {
	_, _, _, ts := setupServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	var doc map[string]any
	json.NewDecoder(resp.Body).Decode(&doc)
	if doc["issuer"] == "" {
		t.Fatal("discovery doc missing issuer")
	}
	if doc["token_endpoint"] == "" {
		t.Fatal("discovery doc missing token_endpoint")
	}
}

func TestServer_JWKS(t *testing.T) {
	_, _, _, ts := setupServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	var jwks map[string]any
	json.NewDecoder(resp.Body).Decode(&jwks)
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("JWKS response has no keys")
	}
}

func TestServer_Revoke(t *testing.T) {
	_, _, _, ts := setupServer(t)
	defer ts.Close()

	resp, _ := http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"foobar"},
		"scope":         {"read"},
	})
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()

	token, _ := result["access_token"].(string)
	if token == "" {
		t.Fatal("no token to revoke")
	}

	revokeResp, err := http.PostForm(ts.URL+"/oauth/revoke", url.Values{
		"token":         {token},
		"client_id":     {"test-client"},
		"client_secret": {"foobar"},
	})
	if err != nil {
		t.Fatal(err)
	}
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke got %d", revokeResp.StatusCode)
	}
}

func TestServer_DeviceAuthorization_notImplemented(t *testing.T) {
	_, _, _, ts := setupServer(t)
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/oauth/device/code", url.Values{
		"client_id": {"test-client"},
		"scope":     {"read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// fosite v0.49 does not support the device grant via compose;
	// the handler returns 501 Not Implemented.
	if resp.StatusCode == http.StatusOK {
		t.Skip("device grant appears to be implemented; update this test")
	}
	// Any non-panic response is acceptable (501, 400, etc.)
}
