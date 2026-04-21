package passport

import "time"

// Config holds runtime configuration for the passport Server.
type Config struct {
	// Issuer is the OAuth2/OIDC issuer URL, e.g. "https://auth.example.com". Required.
	Issuer string

	// LoginURL is where unauthenticated users are redirected during the authorize flow.
	// The server appends ?return=<original_authorize_url>.
	LoginURL string

	// ConsentURL is where users are redirected when consent has not been granted.
	// The server appends ?client_id=…&scopes=…&return=<original_authorize_url>.
	ConsentURL string

	// VerificationURI is the device verification page URL (consumer-owned).
	// Returned as verification_uri in the device authorization response.
	// Required when using the device grant.
	VerificationURI string

	// GlobalSecret is a 32-byte secret used for HMAC signing of refresh tokens and
	// authorization codes. Generate with crypto/rand and store securely.
	GlobalSecret []byte

	AccessTokenTTL  time.Duration // default 1 hour
	RefreshTokenTTL time.Duration // default 30 days
	AuthCodeTTL     time.Duration // default 10 minutes
	DeviceCodeTTL   time.Duration // default 5 minutes
	DeviceInterval  int           // device polling interval in seconds, default 5
}

// DefaultConfig returns a Config with sensible TTL defaults for the given issuer.
// You must populate LoginURL, ConsentURL, and GlobalSecret before use.
func DefaultConfig(issuer string) Config {
	return Config{
		Issuer:          issuer,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		AuthCodeTTL:     10 * time.Minute,
		DeviceCodeTTL:   5 * time.Minute,
		DeviceInterval:  5,
	}
}
