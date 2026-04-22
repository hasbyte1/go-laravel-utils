package passport

import "context"

// AuthorizationCodeStore persists authorization codes.
type AuthorizationCodeStore interface {
	// CreateAuthorizationCode persists a new authorization code. Code.Code must be unique.
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	// GetAuthorizationCode returns the code record.
	// Return ErrCodeNotFound when absent, ErrCodeInvalidated when Active==false.
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	// InvalidateAuthorizationCode marks the code as consumed (sets Active=false).
	// The record must still be returned by GetAuthorizationCode as ErrCodeInvalidated.
	InvalidateAuthorizationCode(ctx context.Context, code string) error
	// DeleteAuthorizationCode permanently removes the code record.
	DeleteAuthorizationCode(ctx context.Context, code string) error
}

// AccessTokenStore persists access token records for revocation tracking.
type AccessTokenStore interface {
	// CreateAccessToken persists a new access token. Signature must be unique.
	CreateAccessToken(ctx context.Context, token *AccessToken) error
	// GetAccessToken returns the token for the given signature.
	// Returns ErrTokenNotFound when absent.
	GetAccessToken(ctx context.Context, signature string) (*AccessToken, error)
	// DeleteAccessToken removes the access token with the given signature.
	DeleteAccessToken(ctx context.Context, signature string) error
	// DeleteAccessTokensBySubject removes all access tokens for the given subject (user ID).
	// This is a caller-facing helper for logout/account-deletion flows; the passport
	// server itself never calls this method.
	DeleteAccessTokensBySubject(ctx context.Context, subject string) error
	// DeleteAccessTokensByRequestID removes all access tokens with the given fosite request ID.
	DeleteAccessTokensByRequestID(ctx context.Context, requestID string) error
}

// RefreshTokenStore persists refresh tokens.
type RefreshTokenStore interface {
	// CreateRefreshToken persists a new refresh token. Signature must be unique.
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	// GetRefreshToken returns the refresh token for the given signature.
	// Returns ErrTokenNotFound when absent.
	// When the token exists but Active==false, return (token, ErrTokenInactive).
	// The record must be returned alongside ErrTokenInactive so callers can build
	// a requester for revocation (mirroring AuthorizationCodeStore.GetAuthorizationCode).
	GetRefreshToken(ctx context.Context, signature string) (*RefreshToken, error)
	// DeleteRefreshToken removes the refresh token with the given signature.
	DeleteRefreshToken(ctx context.Context, signature string) error
	// DeleteRefreshTokensBySubject removes all refresh tokens for the given subject (user ID).
	// This is a caller-facing helper for logout/account-deletion flows; the passport
	// server itself never calls this method.
	DeleteRefreshTokensBySubject(ctx context.Context, subject string) error
	// RevokeRefreshTokensByRequestID sets Active=false for all tokens with the given request ID.
	RevokeRefreshTokensByRequestID(ctx context.Context, requestID string) error
}

// DeviceStore persists device authorization codes.
type DeviceStore interface {
	// CreateDeviceCode persists a new device authorization request.
	CreateDeviceCode(ctx context.Context, req *DeviceCode) error
	// GetDeviceCode returns the device code record for the given device_code string.
	// Returns ErrDeviceNotFound when absent.
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	// GetDeviceCodeByUserCode returns the device code record for the given user_code.
	// Returns ErrDeviceNotFound when absent.
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	// UpdateDeviceCode updates the status and UserID fields of an existing device code.
	UpdateDeviceCode(ctx context.Context, req *DeviceCode) error
	// DeleteDeviceCode removes the device code record with the given device_code string.
	DeleteDeviceCode(ctx context.Context, deviceCode string) error
}
