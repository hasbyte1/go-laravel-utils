package sanctum

import (
	"context"
	"net"
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

// WithTrustedProxyCIDRs registers CIDR ranges that identify trusted reverse
// proxies. When set, X-Forwarded-For is only consulted for requests whose
// direct TCP connection originates from one of these ranges. All other requests
// use RemoteAddr as the authoritative client IP.
//
// Without this option, X-Forwarded-For is ignored entirely and RemoteAddr is
// always used, preventing IP spoofing by clients who inject forged XFF headers.
//
// Example:
//
//	guard := sanctum.NewGuard(svc, csrf,
//	    sanctum.WithTrustedProxyCIDRs("10.0.0.0/8", "172.16.0.0/12"),
//	)
func WithTrustedProxyCIDRs(cidrs ...string) GuardOption {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return func(g *Guard) { g.trustedNets = nets }
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
	trustedNets []*net.IPNet // trusted reverse-proxy CIDRs for XFF resolution
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

// AuthenticateBearer authenticates a bearer token string directly without requiring
// an HTTP request. This is useful for non-HTTP contexts or custom middleware patterns
// like huma router where the context doesn't provide direct access to http.Request.
//
// Parameters:
//   - ctx: The context for the request
//   - bearerToken: The plain-text bearer token string (without "Bearer " prefix)
//   - ip: Optional IP address of the client for tracking purposes
//
// On success it returns a populated [AuthContext]. On failure it returns one of:
// [ErrUnauthorized], [ErrInvalidToken], [ErrTokenExpired].
//
// Note: This method does not run [TokenValidator]s since they require an http.Request.
// Use the standard [Authenticate] method if you need validator support.
//
// Example usage with huma router:
//
//	func HumaAuthMiddleware(guard *sanctum.Guard) func(ctx huma.Context, next func(huma.Context)) {
//		return func(ctx huma.Context, next func(huma.Context)) {
//			// Extract bearer token from Authorization header
//			auth := ctx.Header("Authorization")
//			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
//				huma.WriteErr(ctx.API(), ctx.Context(), 401,
//					"Unauthorized", errors.New("missing bearer token"))
//				return
//			}
//
//			bearerToken := strings.TrimPrefix(auth, "Bearer ")
//
//			// Optional: Extract client IP
//			ip := ctx.Header("X-Real-IP")
//			var ipPtr *string
//			if ip != "" {
//				ipPtr = &ip
//			}
//
//			// Authenticate using the guard
//			authCtx, err := guard.AuthenticateBearer(ctx.Context(), bearerToken, ipPtr)
//			if err != nil {
//				huma.WriteErr(ctx.API(), ctx.Context(), 401, "Unauthorized", err)
//				return
//			}
//
//			// Store auth context for use in handlers
//			ctx.SetContext(sanctum.WithAuthContext(ctx.Context(), authCtx))
//
//			// Continue to next handler
//			next(ctx)
//		}
//	}
func (g *Guard) AuthenticateBearer(ctx context.Context, bearerToken string, ip *string, checkOTP ...bool) (*AuthContext, error) {
	if bearerToken == "" {
		return nil, ErrUnauthorized
	}

	user, token, err := g.service.AuthenticateToken(ctx, bearerToken, ip, checkOTP...)

	if err != nil {
		return nil, err
	}

	ac := &AuthContext{User: user, Token: token}
	return ac, nil
}

func (g *Guard) authenticateBearer(r *http.Request, plainText string, checkOTP ...bool) (*AuthContext, error) {
	ip := extractIPAddress(r, g.trustedNets)

	user, token, err := g.service.AuthenticateToken(r.Context(), plainText, ip, checkOTP...)
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

// extractIPAddress returns the authoritative client IP for this request.
//
// When trustedNets is empty (the default), X-Forwarded-For is ignored and the
// IP is taken directly from RemoteAddr. This is the safe default: clients that
// connect directly can forge any XFF value, so trusting it without knowing the
// request came through a verified proxy would allow IP spoofing.
//
// When trustedNets is non-empty and the direct connection (RemoteAddr) is within
// a trusted range, X-Forwarded-For is consulted. The list is walked right-to-left
// (per RFC 7239 §5.3); the first entry that is NOT in a trusted range is the
// real client IP. If all XFF entries are trusted (or XFF is absent), RemoteAddr
// is returned.
func extractIPAddress(r *http.Request, trustedNets []*net.IPNet) *string {
	remoteHost := remoteAddrHost(r.RemoteAddr)
	if len(trustedNets) == 0 || !isInNets(net.ParseIP(remoteHost), trustedNets) {
		return ptrString(remoteHost)
	}
	// Direct connection is from a trusted proxy — walk XFF right-to-left.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip != nil && !isInNets(ip, trustedNets) {
				return ptrString(ip.String())
			}
		}
	}
	return ptrString(remoteHost)
}

func remoteAddrHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isInNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ptrString returns a pointer to a string.
func ptrString(s string) *string {
	return &s
}
