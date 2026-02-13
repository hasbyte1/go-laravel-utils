package sanctum

import (
	"context"
	"net/http"
	"time"
)

// User is the minimal interface a user model must satisfy.
// The value returned by [GetID] is used to link tokens to their owners.
type User interface {
	// GetID returns the user's unique identifier (e.g. a UUID or integer string).
	GetID() string
}

// TokenRepository defines the persistence operations for [Token] records.
// Callers must provide their own implementation for their chosen storage backend
// (SQL, Redis, etc.). The in-memory reference implementation is in sanctum/inmemory.
type TokenRepository interface {
	// Create persists a new token. The token's ID must be unique.
	Create(ctx context.Context, token *Token) error

	// FindByID retrieves a token by its UUID.
	// Returns [ErrTokenNotFound] when no matching record exists.
	FindByID(ctx context.Context, id string) (*Token, error)

	// FindByHash retrieves a token by its SHA-256 secret hash.
	// Used as a fallback when the token string carries no ID prefix.
	// Returns [ErrTokenNotFound] when no matching record exists.
	FindByHash(ctx context.Context, hash string) (*Token, error)

	// UpdateLastUsedAt records the time the token was most recently authenticated.
	UpdateLastUsedAt(ctx context.Context, id string, t time.Time) error

	// Update persists changes to an existing token.
	// This is used for updating fields like OTP attempts or OTP status.
	Update(ctx context.Context, token *Token) error

	// Revoke removes or invalidates the token with the given ID.
	// Returns [ErrTokenNotFound] if no such token exists.
	Revoke(ctx context.Context, id string) error

	// RevokeAll removes or invalidates every token owned by the given user.
	RevokeAll(ctx context.Context, userID string) error

	// ListByUser returns all tokens owned by the given user.
	ListByUser(ctx context.Context, userID string) ([]*Token, error)

	// PruneExpired deletes all expired tokens and returns the number removed.
	PruneExpired(ctx context.Context) (int64, error)
}

// UserProvider resolves a [User] from a stored user ID.
// Implement this to load users from your own data store.
type UserProvider interface {
	// FindByID returns the user with the given ID.
	// Return (nil, nil) when the user is not found (not an error condition).
	FindByID(ctx context.Context, id string) (User, error)
}

// SessionAuthenticator resolves a [User] from an incoming HTTP request using a
// stateful session mechanism (e.g. a signed cookie).
// Implement this to enable SPA cookie-based authentication.
// Return (nil, nil) when the request carries no valid session.
type SessionAuthenticator interface {
	AuthenticateFromSession(ctx context.Context, r *http.Request) (User, error)
}
