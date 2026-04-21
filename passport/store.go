package passport

import "context"

// AuthorizationCodeStore persists authorization codes.
type AuthorizationCodeStore interface {
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error
	// GetAuthorizationCode returns the code record.
	// Return ErrCodeNotFound when absent, ErrCodeInvalidated when Active==false.
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	// InvalidateAuthorizationCode marks the code as consumed (sets Active=false).
	// The record must still be returned by GetAuthorizationCode as ErrCodeInvalidated.
	InvalidateAuthorizationCode(ctx context.Context, code string) error
	DeleteAuthorizationCode(ctx context.Context, code string) error
}

// AccessTokenStore persists access token records for revocation tracking.
type AccessTokenStore interface {
	CreateAccessToken(ctx context.Context, token *AccessToken) error
	GetAccessToken(ctx context.Context, signature string) (*AccessToken, error)
	DeleteAccessToken(ctx context.Context, signature string) error
	DeleteAccessTokensBySubject(ctx context.Context, subject string) error
	// DeleteAccessTokensByRequestID removes all access tokens with the given fosite request ID.
	DeleteAccessTokensByRequestID(ctx context.Context, requestID string) error
}

// RefreshTokenStore persists refresh tokens.
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	// GetRefreshToken returns the token. Return ErrTokenInactive when Active==false.
	GetRefreshToken(ctx context.Context, signature string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, signature string) error
	DeleteRefreshTokensBySubject(ctx context.Context, subject string) error
	// RevokeRefreshTokensByRequestID sets Active=false for all tokens with the given request ID.
	RevokeRefreshTokensByRequestID(ctx context.Context, requestID string) error
}

// DeviceStore persists device authorization codes.
type DeviceStore interface {
	CreateDeviceCode(ctx context.Context, req *DeviceCode) error
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)
	UpdateDeviceCode(ctx context.Context, req *DeviceCode) error
	DeleteDeviceCode(ctx context.Context, deviceCode string) error
}
