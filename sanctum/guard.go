package sanctum

import (
	"context"
	"net/http"
	"strings"
)

// TokenValidator is a hook invoked after a Bearer token is successfully
// authenticated. Return a non-nil error to reject the request.
//
// Typical uses: IP allow-listing, device fingerprinting, rate limiting.
type TokenValidator func(ctx context.Context, r *http.Request, user User, token *Token) error

// EventType identifies the type of an authentication event.
type EventType int

const (
	// EventAuthenticated fires after a request is successfully authenticated.
	EventAuthenticated EventType = iota
	// EventFailed fires when authentication fails for any reason.
	EventFailed
)

// AuthEvent carries the details of an authentication event delivered to [EventListener]s.
type AuthEvent struct {
	// Type is EventAuthenticated or EventFailed.
	Type EventType
	// Request is the HTTP request that triggered the event.
	Request *http.Request
	// User is the authenticated user. Nil on EventFailed.
	User User
	// Token is the Bearer token used for authentication. Nil for session auth or failure.
	Token *Token
	// Err is the authentication error. Nil on EventAuthenticated.
	Err error
}

// EventListener receives [AuthEvent]s emitted by the [Guard].
type EventListener func(event AuthEvent)

// GuardOption is a functional option for configuring a [Guard].
type GuardOption func(*Guard)

// WithTokenValidator adds a custom post-authentication validation hook.
// Multiple validators are called in the order they are added; the first error
// aborts the chain.
func WithTokenValidator(v TokenValidator) GuardOption {
	return func(g *Guard) {
		g.validators = append(g.validators, v)
	}
}

// WithEventListener registers a listener that will be called on every auth event.
func WithEventListener(l EventListener) GuardOption {
	return func(g *Guard) {
		g.listeners = append(g.listeners, l)
	}
}

// WithSessionAuthenticator enables SPA cookie/session-based authentication.
// When set, requests without a Bearer token are handed to the authenticator.
func WithSessionAuthenticator(sa SessionAuthenticator) GuardOption {
	return func(g *Guard) {
		g.sessionAuth = sa
	}
}

// Guard is the main authentication entry-point. On each request it tries Bearer
// token authentication first, then falls back to session authentication (if a
// [SessionAuthenticator] is configured).
type Guard struct {
	service     *TokenService
	csrf        *CSRFService
	config      Config
	validators  []TokenValidator
	listeners   []EventListener
	sessionAuth SessionAuthenticator
}

// NewGuard constructs a Guard with the given service, CSRF service, and options.
// csrf may be nil when CSRF protection is not needed.
func NewGuard(service *TokenService, csrf *CSRFService, opts ...GuardOption) *Guard {
	g := &Guard{
		service: service,
		csrf:    csrf,
		config:  service.config,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Authenticate attempts to authenticate r using Bearer token auth, falling back
// to session auth when no Bearer token is present and a [SessionAuthenticator] is
// configured.
//
// On success it returns a populated [AuthContext]. On failure it returns one of:
// [ErrUnauthorized], [ErrInvalidToken], [ErrTokenExpired], [ErrCSRFMismatch].
func (g *Guard) Authenticate(r *http.Request) (*AuthContext, error) {
	if plain := extractBearerToken(r); plain != "" {
		return g.authenticateBearer(r, plain)
	}

	if g.sessionAuth != nil {
		return g.authenticateSession(r)
	}

	g.emit(AuthEvent{Type: EventFailed, Request: r, Err: ErrUnauthorized})
	return nil, ErrUnauthorized
}

func (g *Guard) authenticateBearer(r *http.Request, plainText string) (*AuthContext, error) {
	// Extract the user's IP address from the request
	ip := extractIPAddress(r)

	user, token, err := g.service.AuthenticateToken(r.Context(), plainText, ip)
	if err != nil {
		g.emit(AuthEvent{Type: EventFailed, Request: r, Err: err})
		return nil, err
	}

	for _, v := range g.validators {
		if err := v(r.Context(), r, user, token); err != nil {
			g.emit(AuthEvent{Type: EventFailed, Request: r, Err: err})
			return nil, err
		}
	}

	ac := &AuthContext{User: user, Token: token}
	g.emit(AuthEvent{Type: EventAuthenticated, Request: r, User: user, Token: token})
	return ac, nil
}

func (g *Guard) authenticateSession(r *http.Request) (*AuthContext, error) {
	user, err := g.sessionAuth.AuthenticateFromSession(r.Context(), r)
	if err != nil {
		g.emit(AuthEvent{Type: EventFailed, Request: r, Err: err})
		return nil, err
	}
	if user == nil {
		g.emit(AuthEvent{Type: EventFailed, Request: r, Err: ErrUnauthorized})
		return nil, ErrUnauthorized
	}

	// CSRF validation is required for state-changing requests on session auth.
	if g.csrf != nil && !isSafeMethod(r.Method) {
		if err := g.csrf.ValidateRequest(r); err != nil {
			g.emit(AuthEvent{Type: EventFailed, Request: r, Err: err})
			return nil, err
		}
	}

	ac := &AuthContext{User: user, IsSessionAuth: true}
	g.emit(AuthEvent{Type: EventAuthenticated, Request: r, User: user})
	return ac, nil
}

func (g *Guard) emit(e AuthEvent) {
	for _, l := range g.listeners {
		l(e)
	}
}

// extractBearerToken extracts the token value from an "Authorization: Bearer <token>"
// header. Returns an empty string when the header is absent or malformed.
func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return auth[len(prefix):]
	}
	return ""
}

// extractIPAddress extracts the client's IP address from the HTTP request.
// It checks for X-Forwarded-For and X-Real-IP headers (common in proxied environments)
// before falling back to RemoteAddr. Returns a pointer to the IP address string,
// or nil if the address cannot be determined.
func extractIPAddress(r *http.Request) *string {
	// Check X-Forwarded-For header (comma-separated list of IPs in reverse order)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Get the first IP if multiple are present
		if idx := strings.Index(xff, ","); idx > 0 {
			return ptrString(strings.TrimSpace(xff[:idx]))
		}
		return ptrString(strings.TrimSpace(xff))
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return ptrString(xri)
	}

	// Fall back to RemoteAddr (host:port format)
	if r.RemoteAddr != "" {
		if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
			return ptrString(r.RemoteAddr[:idx])
		}
		return ptrString(r.RemoteAddr)
	}

	return nil
}

// ptrString returns a pointer to a string.
func ptrString(s string) *string {
	return &s
}
