package passport

import "errors"

// Sentinel errors returned by passport operations.
//
// Use [errors.Is] for comparisons:
//
//	if errors.Is(err, passport.ErrTokenExpired) { ... }
var (
	// ErrClientNotFound is returned by [ClientStore] when no client
	// matches the requested client_id.
	ErrClientNotFound = errors.New("passport: client not found")

	// ErrCodeNotFound is returned by [AuthorizationCodeStore] when the
	// authorization code does not exist in the store.
	ErrCodeNotFound = errors.New("passport: authorization code not found")

	// ErrCodeInvalidated is returned when an authorization code has already
	// been exchanged and must not be used again (replay protection).
	ErrCodeInvalidated = errors.New("passport: authorization code already used")

	// ErrTokenNotFound is returned by [AccessTokenStore] or [RefreshTokenStore]
	// when no token matches the given signature.
	ErrTokenNotFound = errors.New("passport: token not found")

	// ErrTokenInactive is returned by [RefreshTokenStore] when a refresh token
	// exists but has been revoked (Active == false).
	ErrTokenInactive = errors.New("passport: token is inactive")

	// ErrDeviceNotFound is returned by [DeviceStore] when no device code
	// matches the given device_code or user_code.
	ErrDeviceNotFound = errors.New("passport: device code not found")

	// ErrUnauthorized is returned by [ResourceGuard] when no Bearer token
	// is present in the request.
	ErrUnauthorized = errors.New("passport: unauthorized")

	// ErrInvalidToken is returned by [ResourceGuard] when the Bearer token
	// cannot be parsed or its signature is invalid.
	ErrInvalidToken = errors.New("passport: invalid token")

	// ErrTokenExpired is returned by [ResourceGuard] when the token's exp
	// claim is in the past.
	ErrTokenExpired = errors.New("passport: token expired")

	// ErrKeyNotFound is returned by EphemeralKV.Get when the key does not exist
	// or has expired. The adapter maps this to fosite.ErrNotFound internally.
	ErrKeyNotFound = errors.New("passport: key not found")
)
