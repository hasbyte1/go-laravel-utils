package sanctum_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

// okHandler is a trivial handler that returns 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func newGuardForMiddleware(t testing.TB, userIDs ...string) (*sanctum.Guard, *sanctum.TokenService) {
	t.Helper()
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	for _, id := range userIDs {
		users.Add(&testUser{id: id})
	}
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	return sanctum.NewGuard(svc, csrf), svc
}

func TestAuthenticate_Middleware_Success(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})

	handler := sanctum.Authenticate(g)(okHandler)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthenticate_Middleware_AuthContextInjected(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})

	var capturedAC *sanctum.AuthContext
	check := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAC = sanctum.AuthContextFromRequest(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := sanctum.Authenticate(g)(check)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	handler.ServeHTTP(httptest.NewRecorder(), r)

	if capturedAC == nil {
		t.Fatal("AuthContext was not injected into request context")
	}
	if capturedAC.User.GetID() != "u1" {
		t.Errorf("user ID = %q", capturedAC.User.GetID())
	}
}

func TestAuthenticate_Middleware_NoToken_Returns401(t *testing.T) {
	g, _ := newGuardForMiddleware(t)
	handler := sanctum.Authenticate(g)(okHandler)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthenticate_Middleware_Returns_JSON(t *testing.T) {
	g, _ := newGuardForMiddleware(t)
	handler := sanctum.Authenticate(g)(okHandler)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestRequireAbilities_AllPresent(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"servers:read", "servers:write"},
	})

	handler := sanctum.Authenticate(g)(
		sanctum.RequireAbilities("servers:read", "servers:write")(okHandler),
	)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAbilities_MissingAbility_Returns403(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"servers:read"},
	})

	handler := sanctum.Authenticate(g)(
		sanctum.RequireAbilities("servers:read", "servers:write")(okHandler),
	)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestRequireAbilities_WildcardToken_Passes(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"*"},
	})

	handler := sanctum.Authenticate(g)(
		sanctum.RequireAbilities("anything", "at:all")(okHandler),
	)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for wildcard token, got %d", w.Code)
	}
}

func TestRequireAnyAbility_OnePresent(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"servers:read"},
	})

	handler := sanctum.Authenticate(g)(
		sanctum.RequireAnyAbility("servers:read", "servers:write")(okHandler),
	)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireAnyAbility_NonePresent_Returns403(t *testing.T) {
	g, svc := newGuardForMiddleware(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"billing:read"},
	})

	handler := sanctum.Authenticate(g)(
		sanctum.RequireAnyAbility("servers:read", "servers:write")(okHandler),
	)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestRequireAbilities_SessionAuth_AlwaysAllowed(t *testing.T) {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "spa-user"})
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrfSvc := sanctum.NewCSRFService(sanctum.DefaultConfig())

	sess := &mockSessionAuth{user: &testUser{id: "spa-user"}}
	g := sanctum.NewGuard(svc, csrfSvc, sanctum.WithSessionAuthenticator(sess))

	// Issue and attach CSRF token.
	w0 := httptest.NewRecorder()
	csrfToken, _ := csrfSvc.IssueToken(w0)

	handler := sanctum.Authenticate(g)(
		sanctum.RequireAbilities("admin:only")(okHandler),
	)

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: csrfToken})
	r.Header.Set("X-XSRF-TOKEN", csrfToken)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("SPA session should bypass ability check, got %d", w.Code)
	}
}

func TestRequireAbilities_NoAuthContext_Returns401(t *testing.T) {
	handler := sanctum.RequireAbilities("read")(okHandler)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth context, got %d", w.Code)
	}
}
