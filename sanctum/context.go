package sanctum

import (
	"context"
	"net/http"
)

type contextKey int

const authContextKey contextKey = iota

// AuthContext holds the authentication result for a single HTTP request.
// It is stored in the request context by the [Authenticate] middleware and
// retrieved by downstream handlers via [AuthContextFromRequest].
type AuthContext struct {
	// User is the authenticated user payload.
	//
	// By default this is a value that satisfies [User], but applications may
	// replace it with an enriched domain-specific type in custom middleware.
	// Use [UserAs] for typed access.
	User any

	// Token is the token used for Bearer token authentication.
	// Nil when authentication was performed via a session (SPA auth).
	Token *Token

	// IsSessionAuth reports whether the request was authenticated via a
	// stateful session rather than a Bearer token.
	IsSessionAuth bool
}

// UserAs returns the authenticated user payload from ac as T.
//
// It returns (zero, false) when ac is nil or when the stored user is not of
// type T.
func UserAs[T any](ac *AuthContext) (T, bool) {
	var zero T
	if ac == nil {
		return zero, false
	}
	u, ok := ac.User.(T)
	if !ok {
		return zero, false
	}
	return u, true
}

// SanctumUser returns the authenticated user as the package [User] contract.
//
// It returns (nil, false) when ac is nil or when the stored user does not
// satisfy [User].
func (ac *AuthContext) SanctumUser() (User, bool) {
	if ac == nil {
		return nil, false
	}
	u, ok := ac.User.(User)
	if !ok {
		return nil, false
	}
	return u, true
}

// WithAuthContext returns a copy of ctx that carries the given [AuthContext].
func WithAuthContext(ctx context.Context, ac *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, ac)
}

// AuthContextFromContext retrieves the [AuthContext] stored in ctx.
// Returns nil if no AuthContext has been attached.
func AuthContextFromContext(ctx context.Context) *AuthContext {
	ac, _ := ctx.Value(authContextKey).(*AuthContext)
	return ac
}

// AuthContextFromRequest retrieves the [AuthContext] from the request's context.
// Returns nil if the [Authenticate] middleware has not run.
func AuthContextFromRequest(r *http.Request) *AuthContext {
	return AuthContextFromContext(r.Context())
}
