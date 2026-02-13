// Package sanctum provides Laravel Sanctum-inspired API token and SPA authentication for Go.
//
// It is DB-agnostic: all persistence is delegated to user-provided implementations of
// [TokenRepository] and [UserProvider]. A thread-safe in-memory reference implementation
// is available in the sub-package sanctum/inmemory.
//
// # Token authentication
//
// Tokens are generated with [TokenService.CreateToken]. The returned plain-text token is
// in the format "{uuid}|{base64url-secret}" and must be delivered to the user once; it
// cannot be recovered. Only the SHA-256 hash of the secret portion is stored.
//
// # SPA authentication
//
// Cookie/session-based authentication is enabled by supplying a [SessionAuthenticator]
// via [WithSessionAuthenticator]. The [CSRFService] implements the double-submit cookie
// pattern for CSRF protection.
//
// # Middleware
//
// [Authenticate], [RequireAbilities], and [RequireAnyAbility] provide net/http-compatible
// middleware that integrate with any standard Go HTTP framework.
package sanctum

import "errors"

var (
	// ErrTokenNotFound is returned when a token cannot be found in the repository.
	ErrTokenNotFound = errors.New("sanctum: token not found")

	// ErrTokenExpired is returned when a token has passed its expiry time.
	ErrTokenExpired = errors.New("sanctum: token expired")

	// ErrTokenRevoked is returned when a token has been revoked.
	ErrTokenRevoked = errors.New("sanctum: token revoked")

	// ErrInvalidToken is returned when a token string is malformed or fails hash verification.
	ErrInvalidToken = errors.New("sanctum: invalid token")

	// ErrUnauthorized is returned when no valid authentication is provided.
	ErrUnauthorized = errors.New("sanctum: unauthorized")

	// ErrForbidden is returned when authentication succeeded but the token lacks a required ability.
	ErrForbidden = errors.New("sanctum: forbidden")

	// ErrCSRFMismatch is returned when the CSRF header does not match the CSRF cookie.
	ErrCSRFMismatch = errors.New("sanctum: CSRF token mismatch")

	// ErrInvalidCSRFToken is returned when the CSRF cookie is absent or malformed.
	ErrInvalidCSRFToken = errors.New("sanctum: invalid CSRF token")

	// ErrOTPRequired is returned when a token requires OTP verification but none was provided.
	ErrOTPRequired = errors.New("sanctum: OTP verification required")

	// ErrInvalidOTP is returned when the provided OTP does not match the stored OTP.
	ErrInvalidOTP = errors.New("sanctum: invalid OTP")

	// ErrOTPExhausted is returned when the maximum OTP verification attempts have been exceeded.
	ErrOTPExhausted = errors.New("sanctum: OTP verification attempts exhausted")
)
