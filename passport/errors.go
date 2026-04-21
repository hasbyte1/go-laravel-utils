package passport

import "errors"

var (
	ErrClientNotFound    = errors.New("passport: client not found")
	ErrCodeNotFound      = errors.New("passport: authorization code not found")
	ErrCodeInvalidated   = errors.New("passport: authorization code already used")
	ErrTokenNotFound     = errors.New("passport: token not found")
	ErrTokenInactive     = errors.New("passport: token is inactive")
	ErrDeviceNotFound    = errors.New("passport: device code not found")
	ErrUnauthorized      = errors.New("passport: unauthorized")
	ErrInvalidToken      = errors.New("passport: invalid token")
	ErrTokenExpired      = errors.New("passport: token expired")
)
