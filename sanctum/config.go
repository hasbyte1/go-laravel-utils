package sanctum

import "time"

// Config holds the runtime configuration for a [Guard] and its sub-services.
type Config struct {
	// TokenBytes is the number of random bytes used for token secrets.
	// Defaults to 40 if zero or negative.
	TokenBytes int

	// DefaultExpiry is the default token lifetime. A zero value means tokens
	// never expire unless an explicit ExpiresAt is supplied at creation time.
	DefaultExpiry time.Duration

	// StatefulDomains lists the host names (e.g. "example.com", "app.example.com")
	// for which cookie/session-based SPA authentication is enabled.
	// Leave empty to disable domain-based SPA gating.
	StatefulDomains []string

	// CSRFCookieName is the name of the CSRF cookie sent to the browser.
	// Defaults to "XSRF-TOKEN".
	CSRFCookieName string

	// CSRFHeaderName is the request header the browser must echo the CSRF value in.
	// Defaults to "X-XSRF-TOKEN".
	CSRFHeaderName string

	// CSRFCookieSecure sets the Secure flag on the CSRF cookie.
	// Enable in production (requires HTTPS).
	CSRFCookieSecure bool

	// CSRFCookieSameSite controls the SameSite attribute of the CSRF cookie.
	// Accepted values: "Lax" (default), "Strict", "None".
	CSRFCookieSameSite string
}

// DefaultConfig returns a [Config] populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		TokenBytes:         40,
		CSRFCookieName:     "XSRF-TOKEN",
		CSRFHeaderName:     "X-XSRF-TOKEN",
		CSRFCookieSameSite: "Lax",
	}
}
