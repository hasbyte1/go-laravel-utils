package sanctum

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	tokenRandomBytes = 40
	// MaxOTPAttempts is the maximum number of failed OTP verification attempts allowed.
	MaxOTPAttempts = 3
)

// Token represents a personal access token stored in the repository.
type Token struct {
	// ID is the unique identifier for the token (UUID v4).
	ID string

	// UserID is the ID of the user who owns this token.
	UserID string

	// Name is a human-readable label for the token (e.g. "My App").
	Name string

	// Hash is the SHA-256 hex digest of the token secret (the part after "|").
	// This is the value stored in the database — never store the plain-text secret.
	Hash string

	// Abilities lists the permissions granted by this token.
	// A single wildcard entry ("*") grants all abilities.
	Abilities []string

	// CreatedAt is when the token record was created.
	CreatedAt time.Time

	// UpdatedAt is when the token record was last modified.
	UpdatedAt time.Time

	// LastUsedAt is when the token was last authenticated. Nil if never used.
	LastUsedAt *time.Time

	// ExpiresAt is when the token expires. Nil means the token never expires.
	ExpiresAt *time.Time

	// OTPHash is the SHA-256 hex digest of the OTP code. Empty string if not set.
	// Never store the plain-text OTP; only the hash is persisted.
	OTPHash string

	// OTPAttempts is the number of failed OTP verification attempts.
	OTPAttempts int8

	// OTPType identifies the method used to generate the OTP (e.g., "sms", "email", "totp").
	OTPType string

	// ActiveRole is the currently active role for this token (string/JSON).
	// Applications with multiple roles can use this to store the active role information.
	// This can be a JSON string containing role details or any other text information.
	ActiveRole string
}

// IsExpired reports whether the token has passed its expiry time.
func (t *Token) IsExpired() bool {
	return t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt)
}

// RequiresOTP reports whether the token requires OTP verification.
func (t *Token) RequiresOTP() bool {
	return t.OTPHash != ""
}

// IsOTPExhausted reports whether the token has exceeded the maximum OTP verification attempts.
func (t *Token) IsOTPExhausted() bool {
	return t.OTPAttempts >= MaxOTPAttempts
}

// NewTokenResult is returned by [TokenService.CreateToken]. It carries both the
// persisted token record and the one-time plain-text token string that must be
// delivered to the user. The plain-text string cannot be recovered after creation.
type NewTokenResult struct {
	// Token is the persisted token record (without the plain-text secret).
	Token *Token

	// PlainText is the full token string in the format "{id}|{secret}".
	// Show this to the user exactly once.
	PlainText string
}

// generateToken creates a new Token and its plain-text representation.
// Token format: {uuid}|{base64url(random bytes)}
// Only sha256(secret) is stored in Token.Hash.
// If otp is not nil, the token will require OTP verification before use.
func generateToken(userID, name string, abilities []string, expiresAt *time.Time, otp *int32, otpType, activeRole string) (*NewTokenResult, error) {
	id, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("sanctum: generate token ID: %w", err)
	}

	secret, err := randomBase64URL(tokenRandomBytes)
	if err != nil {
		return nil, fmt.Errorf("sanctum: generate token secret: %w", err)
	}

	plainText := id + "|" + secret
	hash := HashToken(secret)

	now := time.Now()
	abs := make([]string, len(abilities))
	copy(abs, abilities)

	otpHash := ""
	if otp != nil {
		otpHash = HashOTP(*otp)
	}

	return &NewTokenResult{
		Token: &Token{
			ID:          id,
			UserID:      userID,
			Name:        name,
			Hash:        hash,
			Abilities:   abs,
			CreatedAt:   now,
			UpdatedAt:   now,
			ExpiresAt:   expiresAt,
			OTPHash:     otpHash,
			OTPAttempts: 0,
			OTPType:     otpType,
			ActiveRole:  activeRole,
		},
		PlainText: plainText,
	}, nil
}

// HashToken returns the SHA-256 hex digest of a token secret.
// Pass only the secret portion (after "|"), not the full plain-text token.
func HashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// HashOTP returns the SHA-256 hex digest of an OTP code.
func HashOTP(otp int32) string {
	s := fmt.Sprintf("%d", otp)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// parseTokenID splits a plain-text token string into its ID and secret parts.
// Expected format: "{id}|{secret}". Returns [ErrInvalidToken] if the format is invalid.
func parseTokenID(plainText string) (id, secret string, err error) {
	idx := strings.IndexByte(plainText, '|')
	if idx < 1 || idx == len(plainText)-1 {
		return "", "", ErrInvalidToken
	}
	return plainText[:idx], plainText[idx+1:], nil
}

// randomBase64URL returns n cryptographically random bytes encoded as base64url (no padding).
func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateUUID generates a random UUID version 4.
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
