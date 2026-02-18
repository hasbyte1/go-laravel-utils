package sanctum_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

// mockSessionAuth implements SessionAuthenticator for tests.
type mockSessionAuth struct {
	user sanctum.User
	err  error
}

func (m *mockSessionAuth) AuthenticateFromSession(_ context.Context, _ *http.Request) (sanctum.User, error) {
	return m.user, m.err
}

func newTestGuard(t testing.TB, userIDs ...string) (*sanctum.Guard, *sanctum.TokenService) {
	t.Helper()
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	for _, id := range userIDs {
		users.Add(&testUser{id: id})
	}
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	g := sanctum.NewGuard(svc, csrf)
	return g, svc
}

func TestGuard_BearerTokenAuth(t *testing.T) {
	g, svc := newTestGuard(t, "u1")

	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)

	ac, err := g.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ac.User.GetID() != "u1" {
		t.Errorf("user ID = %q", ac.User.GetID())
	}
	if ac.IsSessionAuth {
		t.Error("should not be session auth")
	}
	if ac.Token == nil {
		t.Error("token should be set")
	}
}

func TestGuard_NoAuthReturnsUnauthorized(t *testing.T) {
	g, _ := newTestGuard(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := g.Authenticate(r)
	if !errors.Is(err, sanctum.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestGuard_InvalidBearerToken(t *testing.T) {
	g, _ := newTestGuard(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer invalid|token")
	_, err := g.Authenticate(r)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestGuard_SessionAuth(t *testing.T) {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "spa-user"})
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())

	sess := &mockSessionAuth{user: &testUser{id: "spa-user"}}
	g := sanctum.NewGuard(svc, csrf, sanctum.WithSessionAuthenticator(sess))

	r := httptest.NewRequest(http.MethodGet, "/", nil) // GET — safe, no CSRF needed
	ac, err := g.Authenticate(r)
	if err != nil {
		t.Fatalf("session auth: %v", err)
	}
	if !ac.IsSessionAuth {
		t.Error("expected IsSessionAuth = true")
	}
	if ac.User.GetID() != "spa-user" {
		t.Errorf("user ID = %q", ac.User.GetID())
	}
}

func TestGuard_SessionAuth_CSRFRequired(t *testing.T) {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "spa-user"})
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	sess := &mockSessionAuth{user: &testUser{id: "spa-user"}}
	g := sanctum.NewGuard(svc, csrf, sanctum.WithSessionAuthenticator(sess))

	// POST without CSRF cookie/header — should fail.
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	_, err := g.Authenticate(r)
	if !errors.Is(err, sanctum.ErrInvalidCSRFToken) {
		t.Errorf("expected ErrInvalidCSRFToken, got %v", err)
	}
}

func TestGuard_SessionAuth_WithValidCSRF(t *testing.T) {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "spa-user"})
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrfSvc := sanctum.NewCSRFService(sanctum.DefaultConfig())
	sess := &mockSessionAuth{user: &testUser{id: "spa-user"}}
	g := sanctum.NewGuard(svc, csrfSvc, sanctum.WithSessionAuthenticator(sess))

	// Issue CSRF token.
	w := httptest.NewRecorder()
	token, _ := csrfSvc.IssueToken(w)

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: token})
	r.Header.Set("X-XSRF-TOKEN", token)

	ac, err := g.Authenticate(r)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if !ac.IsSessionAuth {
		t.Error("expected IsSessionAuth = true")
	}
}

func TestGuard_SessionAuth_NoUser(t *testing.T) {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	sess := &mockSessionAuth{user: nil} // no session
	g := sanctum.NewGuard(svc, csrf, sanctum.WithSessionAuthenticator(sess))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := g.Authenticate(r)
	if !errors.Is(err, sanctum.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestGuard_TokenValidator_Rejects(t *testing.T) {
	g, svc := newTestGuard(t, "u1")

	// Add a custom validator that always rejects.
	rejector := sanctum.TokenValidator(func(ctx context.Context, r *http.Request, user sanctum.User, token *sanctum.Token) error {
		return errors.New("IP not allowed")
	})
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "u1"})
	svc2 := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	g2 := sanctum.NewGuard(svc2, csrf, sanctum.WithTokenValidator(rejector))

	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})
	// Create a matching token in svc2's repo
	result2, _ := svc2.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result2.PlainText)

	_, err := g2.Authenticate(r)
	if err == nil {
		t.Error("expected validator to reject")
	}
	_ = result // silence unused warning
	_ = g
}

func TestGuard_EventListener_AuthSuccess(t *testing.T) {
	var fired []sanctum.EventType
	listener := sanctum.EventListener(func(e sanctum.AuthEvent) {
		fired = append(fired, e.Type)
	})

	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "u1"})
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	g := sanctum.NewGuard(svc, csrf, sanctum.WithEventListener(listener))

	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	g.Authenticate(r)

	if len(fired) != 1 || fired[0] != sanctum.EventAuthenticated {
		t.Errorf("expected [EventAuthenticated], got %v", fired)
	}
}

func TestGuard_EventListener_AuthFailed(t *testing.T) {
	var fired []sanctum.EventType
	listener := sanctum.EventListener(func(e sanctum.AuthEvent) {
		fired = append(fired, e.Type)
	})

	repo := inmemory.New()
	users := inmemory.NewUserStore()
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	g := sanctum.NewGuard(svc, csrf, sanctum.WithEventListener(listener))

	r := httptest.NewRequest(http.MethodGet, "/", nil) // no auth
	g.Authenticate(r)

	if len(fired) != 1 || fired[0] != sanctum.EventFailed {
		t.Errorf("expected [EventFailed], got %v", fired)
	}
}

func TestGuard_BearerTokenCaseInsensitive(t *testing.T) {
	g, svc := newTestGuard(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "bearer "+result.PlainText) // lowercase

	_, err := g.Authenticate(r)
	if err != nil {
		t.Errorf("bearer (lowercase) should be accepted: %v", err)
	}
}

func TestGuard_AuthenticateBearer(t *testing.T) {
	g, svc := newTestGuard(t, "u1")

	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})

	// Test successful authentication
	ip := "192.168.1.1"
	ac, err := g.AuthenticateBearer(context.Background(), result.PlainText, &ip)
	if err != nil {
		t.Fatalf("AuthenticateBearer: %v", err)
	}
	if ac.User.GetID() != "u1" {
		t.Errorf("user ID = %q, want %q", ac.User.GetID(), "u1")
	}
	if ac.Token == nil {
		t.Error("token should be set")
	}
	if ac.IsSessionAuth {
		t.Error("should not be session auth")
	}
}

func TestGuard_AuthenticateBearer_EmptyToken(t *testing.T) {
	g, _ := newTestGuard(t)

	_, err := g.AuthenticateBearer(context.Background(), "", nil)
	if !errors.Is(err, sanctum.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for empty token, got %v", err)
	}
}

func TestGuard_AuthenticateBearer_InvalidToken(t *testing.T) {
	g, _ := newTestGuard(t)

	_, err := g.AuthenticateBearer(context.Background(), "invalid|token", nil)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestGuard_AuthenticateBearer_WithoutIP(t *testing.T) {
	g, svc := newTestGuard(t, "u2")

	result, _ := svc.CreateToken(context.Background(), "u2", sanctum.CreateTokenOptions{})

	// Test without IP address
	ac, err := g.AuthenticateBearer(context.Background(), result.PlainText, nil)
	if err != nil {
		t.Fatalf("AuthenticateBearer without IP: %v", err)
	}
	if ac.User.GetID() != "u2" {
		t.Errorf("user ID = %q, want %q", ac.User.GetID(), "u2")
	}
}
