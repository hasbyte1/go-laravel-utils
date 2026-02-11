package sanctum_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
)

func newTestCSRF() *sanctum.CSRFService {
	return sanctum.NewCSRFService(sanctum.DefaultConfig())
}

func TestCSRF_IssueTokenSetsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	token, err := newTestCSRF().IssueToken(w)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	resp := w.Result()
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "XSRF-TOKEN" {
			found = true
			if c.Value != token {
				t.Errorf("cookie value %q != token %q", c.Value, token)
			}
			if c.HttpOnly {
				t.Error("CSRF cookie must not be HttpOnly (JS must read it)")
			}
		}
	}
	if !found {
		t.Error("XSRF-TOKEN cookie not set")
	}
}

func TestCSRF_IssueToken_Unique(t *testing.T) {
	csrf := newTestCSRF()
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		tok, _ := csrf.IssueToken(httptest.NewRecorder())
		if seen[tok] {
			t.Fatal("duplicate CSRF token")
		}
		seen[tok] = true
	}
}

func TestCSRF_ValidateRequest_SafeMethods(t *testing.T) {
	csrf := newTestCSRF()
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		r := httptest.NewRequest(method, "/", nil)
		if err := csrf.ValidateRequest(r); err != nil {
			t.Errorf("%s: expected nil error, got %v", method, err)
		}
	}
}

func TestCSRF_ValidateRequest_Valid(t *testing.T) {
	csrf := newTestCSRF()
	token := "mycsrftoken"

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: token})
	r.Header.Set("X-XSRF-TOKEN", token)

	if err := csrf.ValidateRequest(r); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCSRF_ValidateRequest_MissingCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("X-XSRF-TOKEN", "sometoken")
	err := newTestCSRF().ValidateRequest(r)
	if !errors.Is(err, sanctum.ErrInvalidCSRFToken) {
		t.Errorf("expected ErrInvalidCSRFToken, got %v", err)
	}
}

func TestCSRF_ValidateRequest_MissingHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "tok"})
	err := newTestCSRF().ValidateRequest(r)
	if !errors.Is(err, sanctum.ErrCSRFMismatch) {
		t.Errorf("expected ErrCSRFMismatch, got %v", err)
	}
}

func TestCSRF_ValidateRequest_Mismatch(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "cookie-value"})
	r.Header.Set("X-XSRF-TOKEN", "different-value")
	err := newTestCSRF().ValidateRequest(r)
	if !errors.Is(err, sanctum.ErrCSRFMismatch) {
		t.Errorf("expected ErrCSRFMismatch, got %v", err)
	}
}

func TestCSRF_ValidateRequest_DeleteMethod(t *testing.T) {
	csrf := newTestCSRF()
	token := "tok"
	r := httptest.NewRequest(http.MethodDelete, "/", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: token})
	r.Header.Set("X-XSRF-TOKEN", token)
	if err := csrf.ValidateRequest(r); err != nil {
		t.Errorf("DELETE with valid CSRF: %v", err)
	}
}

func TestCSRF_CustomCookieAndHeader(t *testing.T) {
	cfg := sanctum.DefaultConfig()
	cfg.CSRFCookieName = "MY-CSRF"
	cfg.CSRFHeaderName = "X-MY-CSRF"
	csrf := sanctum.NewCSRFService(cfg)

	token := "custom"
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: "MY-CSRF", Value: token})
	r.Header.Set("X-MY-CSRF", token)

	if err := csrf.ValidateRequest(r); err != nil {
		t.Errorf("custom names: %v", err)
	}
}
