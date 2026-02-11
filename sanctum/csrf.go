package sanctum

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"
)

const csrfTokenBytes = 32

// CSRFService implements the double-submit cookie pattern for CSRF protection.
//
// On page load the SPA calls a dedicated endpoint that invokes [IssueToken]; this
// sets a readable (non-HttpOnly) cookie containing a random token. For every
// subsequent state-changing request the JavaScript framework must copy the cookie
// value into the request header named by Config.CSRFHeaderName. [ValidateRequest]
// confirms they match.
//
// Safe HTTP methods (GET, HEAD, OPTIONS, TRACE) are exempt from CSRF validation.
type CSRFService struct {
	config Config
}

// NewCSRFService creates a [CSRFService] using the provided configuration.
// Missing cookie/header names are replaced with their defaults.
func NewCSRFService(cfg Config) *CSRFService {
	if cfg.CSRFCookieName == "" {
		cfg.CSRFCookieName = "XSRF-TOKEN"
	}
	if cfg.CSRFHeaderName == "" {
		cfg.CSRFHeaderName = "X-XSRF-TOKEN"
	}
	return &CSRFService{config: cfg}
}

// IssueToken generates a fresh random CSRF token, writes it as a cookie on w,
// and returns the plain-text token value.
func (s *CSRFService) IssueToken(w http.ResponseWriter) (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	sameSite := http.SameSiteLaxMode
	switch s.config.CSRFCookieSameSite {
	case "Strict":
		sameSite = http.SameSiteStrictMode
	case "None":
		sameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.config.CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // must be readable by JavaScript
		Secure:   s.config.CSRFCookieSecure,
		SameSite: sameSite,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	return token, nil
}

// ValidateRequest checks that the CSRF token echoed in the request header matches
// the value stored in the CSRF cookie.
//
// Returns nil for safe methods (GET, HEAD, OPTIONS, TRACE).
// Returns [ErrInvalidCSRFToken] when the cookie is missing or empty.
// Returns [ErrCSRFMismatch] when the header is absent or does not match the cookie.
func (s *CSRFService) ValidateRequest(r *http.Request) error {
	if isSafeMethod(r.Method) {
		return nil
	}

	cookie, err := r.Cookie(s.config.CSRFCookieName)
	if err != nil || cookie.Value == "" {
		return ErrInvalidCSRFToken
	}

	header := r.Header.Get(s.config.CSRFHeaderName)
	if header == "" {
		return ErrCSRFMismatch
	}

	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		return ErrCSRFMismatch
	}

	return nil
}

// isSafeMethod reports whether the HTTP method is considered safe (read-only).
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}
