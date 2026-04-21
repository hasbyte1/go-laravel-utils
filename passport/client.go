package passport

import "context"

// ClientStore retrieves registered OAuth2 clients by ID.
// Implement this against your own database.
type ClientStore interface {
	// GetClient returns the client with the given ID.
	// Return ErrClientNotFound when the client does not exist.
	GetClient(ctx context.Context, id string) (*OAuthClient, error)
}
