package passport

import "time"

// DeviceStatus constants for DeviceCode.Status.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
)

// OAuthClient represents a registered OAuth2 client application.
type OAuthClient struct {
	// ID is the OAuth2 client_id, e.g. "my-app". Must be unique across all clients.
	ID string

	// SecretHash is a bcrypt hash of the client secret.
	// fosite uses bcrypt for client authentication. Never store the plaintext secret.
	SecretHash string

	// Name is a human-readable label shown on consent screens.
	Name string

	// RedirectURIs lists the allowed redirect targets for this client.
	RedirectURIs []string

	// GrantTypes lists the grant types this client may use:
	// "authorization_code", "client_credentials", "refresh_token",
	// "urn:ietf:params:oauth:grant-type:device_code".
	GrantTypes []string

	// Scopes lists the OAuth2 scopes this client is permitted to request.
	Scopes []string

	// Public marks clients with no secret (e.g. SPAs, CLIs); PKCE is required for these.
	Public bool
}

// AuthorizationCode represents a stored authorization code.
// SessionData is an opaque JSON blob managed by the passport package — store it
// as a text/blob column and return it unchanged.
type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scopes              []string
	ExpiresAt           time.Time
	CodeChallenge       string
	CodeChallengeMethod string // "S256" or "plain"
	Nonce               string // OIDC
	Active              bool   // false after first exchange (single-use)
	SessionData         []byte // serialized fosite session — treat as opaque
}

// AccessToken represents a stored access token record (used for revocation tracking).
// SessionData is an opaque JSON blob managed by the passport package.
type AccessToken struct {
	Signature   string // JWT signature segment, used as the storage key
	RequestID   string // fosite request ID, used for bulk revocation
	ClientID    string
	UserID      string // empty for client_credentials
	Scopes      []string
	ExpiresAt   time.Time
	SessionData []byte
}

// RefreshToken represents a stored refresh token.
// SessionData is an opaque JSON blob managed by the passport package.
type RefreshToken struct {
	Signature   string
	RequestID   string
	ClientID    string
	UserID      string
	Scopes      []string
	ExpiresAt   time.Time
	Active      bool   // false after rotation (set by RevokeRefreshTokensByRequestID)
	SessionData []byte
}

// DeviceCode represents a device authorization request.
// SessionData is an opaque JSON blob managed by the passport package.
type DeviceCode struct {
	DeviceCode  string
	UserCode    string
	RequestID   string // fosite request ID
	ClientID    string
	Scopes      []string
	ExpiresAt   time.Time
	Interval    int    // polling interval in seconds
	Status      string // DeviceStatusPending | DeviceStatusApproved | DeviceStatusDenied
	UserID      string // populated when Status == DeviceStatusApproved
	SessionData []byte
}
