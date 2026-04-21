package passport

import (
	"context"
	"net/http"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
)

// UserSessionProvider resolves the currently authenticated user from an HTTP request.
// Used during the authorize flow. Return (nil, nil) when no user is authenticated —
// the Server will redirect to Config.LoginURL.
type UserSessionProvider interface {
	GetUser(ctx context.Context, r *http.Request) (sanctum.User, error)
}

// ConsentProvider manages user consent for OAuth2 clients.
type ConsentProvider interface {
	// IsConsentGranted reports whether userID has already consented to all given
	// scopes for clientID.
	IsConsentGranted(ctx context.Context, userID, clientID string, scopes []string) (bool, error)
	// SaveConsent records that userID has consented to scopes for clientID.
	SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error
	// RevokeConsent removes consent for userID + clientID (e.g. on token revocation).
	RevokeConsent(ctx context.Context, userID, clientID string) error
}

// UserInfoProvider returns OIDC claims for a user given the granted scopes.
type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, user sanctum.User, scopes []string) (map[string]any, error)
}
