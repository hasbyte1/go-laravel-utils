package sanctum

import (
	"context"
	"fmt"
	"time"
)

// CreateTokenOptions holds the parameters for [TokenService.CreateToken].
type CreateTokenOptions struct {
	// Name is a human-readable label for the token (e.g. "GitHub Actions").
	Name string

	// Abilities lists the permissions the token should grant.
	// An empty slice defaults to wildcard access (["*"]).
	Abilities []string

	// ExpiresAt sets an explicit expiry time for the token.
	// When nil, Config.DefaultExpiry is applied; if that is also zero, the token
	// never expires.
	ExpiresAt *time.Time

	// OTP is an optional one-time password code for additional security.
	// When set, OTP verification is required before the token can be used.
	OTP *int32

	// OTPType identifies the method used to generate the OTP (e.g., "sms", "email", "totp").
	// Only used if OTP is set. Nil if not set.
	OTPType *string

	// ActiveRole is the currently active role for this token (string/JSON).
	// Applications with multiple roles can use this to store the active role information.
	// This can be a JSON string containing role details or any other text information.
	// Nil if not set.
	ActiveRole *string

	// SwitchToUserID is the ID of the user to switch to, allowing an admin or authorized
	// user to authenticate as if they were another user. Nil if no switch is active.
	SwitchToUserID *string
}

// TokenService provides the core token lifecycle operations.
// All storage calls are delegated to [TokenRepository] and [UserProvider],
// keeping the business logic independent of any database technology.
type TokenService struct {
	repo   TokenRepository
	users  UserProvider
	config Config
}

// NewTokenService constructs a [TokenService] with the supplied dependencies.
func NewTokenService(repo TokenRepository, users UserProvider, cfg Config) *TokenService {
	if cfg.TokenBytes <= 0 {
		cfg.TokenBytes = 40
	}
	return &TokenService{repo: repo, users: users, config: cfg}
}

// CreateToken generates a new personal access token for userID and persists it.
// The returned [NewTokenResult] contains the one-time plain-text token string
// that must be delivered to the user, as well as the stored [Token] record.
// If OTP is provided in options, OTP verification will be required before token usage.
func (s *TokenService) CreateToken(ctx context.Context, userID string, opts CreateTokenOptions) (*NewTokenResult, error) {
	abilities := opts.Abilities
	if len(abilities) == 0 {
		abilities = []string{"*"}
	}

	expiresAt := opts.ExpiresAt
	if expiresAt == nil && s.config.DefaultExpiry > 0 {
		t := time.Now().Add(s.config.DefaultExpiry)
		expiresAt = &t
	}

	result, err := generateToken(userID, opts.Name, abilities, expiresAt, opts.OTP, opts.OTPType, opts.ActiveRole, opts.SwitchToUserID)
	if err != nil {
		return nil, fmt.Errorf("sanctum: create token: %w", err)
	}

	if err := s.repo.Create(ctx, result.Token); err != nil {
		return nil, fmt.Errorf("sanctum: persist token: %w", err)
	}

	return result, nil
}

// AuthenticateToken validates a plain-text Bearer token string and returns the
// associated [User] and [Token] on success.
//
// Flow:
//  1. If the string is in "{id}|{secret}" format, look up the token by ID and
//     verify sha256(secret) against the stored hash.
//  2. Otherwise fall back to a hash-based lookup (for tokens without an ID prefix).
//  3. Check token expiry and OTP requirements.
//
// The userIP parameter is optional and tracks the IP address of the user at authentication time.
// Returns [ErrOTPRequired] if the token requires OTP verification before use.
// LastUsedAt and UserIP are updated as a best-effort side effect; auth is not failed if the
// update itself errors.
func (s *TokenService) AuthenticateToken(ctx context.Context, plainText string, userIP *string) (User, *Token, error) {
	id, secret, err := parseTokenID(plainText)
	if err != nil {
		// No valid ID prefix — fall back to full-string hash lookup.
		hash := HashToken(plainText)
		return s.authenticateByHash(ctx, hash, userIP)
	}

	token, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	if HashToken(secret) != token.Hash {
		return nil, nil, ErrInvalidToken
	}

	if token.IsExpired() {
		return nil, nil, ErrTokenExpired
	}

	// Check if OTP verification is required
	if token.RequiresOTP() {
		return nil, nil, ErrOTPRequired
	}

	user, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("sanctum: load user: %w", err)
	}
	if user == nil {
		return nil, nil, ErrTokenNotFound
	}

	now := time.Now()
	_ = s.repo.UpdateLastUsedAtAndUserIP(ctx, token.ID, now, userIP)
	return user, token, nil
}

func (s *TokenService) authenticateByHash(ctx context.Context, hash string, userIP *string) (User, *Token, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		return nil, nil, err
	}

	if token.IsExpired() {
		return nil, nil, ErrTokenExpired
	}

	// Check if OTP verification is required
	if token.RequiresOTP() {
		return nil, nil, ErrOTPRequired
	}

	user, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("sanctum: load user: %w", err)
	}
	if user == nil {
		return nil, nil, ErrTokenNotFound
	}

	now := time.Now()
	_ = s.repo.UpdateLastUsedAtAndUserIP(ctx, token.ID, now, userIP)
	return user, token, nil
}

// RevokeToken revokes the token identified by tokenID.
func (s *TokenService) RevokeToken(ctx context.Context, tokenID string) error {
	if err := s.repo.Revoke(ctx, tokenID); err != nil {
		return fmt.Errorf("sanctum: revoke token: %w", err)
	}
	return nil
}

// RevokeAllTokens revokes every token belonging to userID.
func (s *TokenService) RevokeAllTokens(ctx context.Context, userID string) error {
	if err := s.repo.RevokeAll(ctx, userID); err != nil {
		return fmt.Errorf("sanctum: revoke all tokens: %w", err)
	}
	return nil
}

// ListTokens returns all tokens belonging to userID.
func (s *TokenService) ListTokens(ctx context.Context, userID string) ([]*Token, error) {
	tokens, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("sanctum: list tokens: %w", err)
	}
	return tokens, nil
}

// PruneExpired deletes all expired tokens and returns the number removed.
func (s *TokenService) PruneExpired(ctx context.Context) (int64, error) {
	n, err := s.repo.PruneExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("sanctum: prune expired: %w", err)
	}
	return n, nil
}

// VerifyOTP verifies the provided OTP code against the token's stored OTP.
// If the primary OTP doesn't match and a fallbackOTP is provided, it verifies against that as well.
// On successful verification, the OTP is cleared from the token.
// On failed verification, OTPAttempts is incremented, and if max attempts are reached,
// the token is automatically revoked.
//
// Parameters:
//   - tokenID: The token identifier to verify OTP for
//   - providedOTP: The primary OTP code provided by the user
//   - fallbackOTP: Optional fallback OTP code (e.g., from TOTP) to check if primary doesn't match
//   - otpAbilities: Optional ability requirements for OTP verification
//
// Returns errors:
//   - ErrTokenNotFound: token does not exist
//   - ErrOTPRequired: token requires OTP but none is set (invalid state)
//   - ErrInvalidOTP: provided OTP does not match stored OTP or fallback OTP
//   - ErrOTPExhausted: maximum OTP verification attempts exceeded (token is revoked)
func (s *TokenService) VerifyOTP(ctx context.Context, tokenID string, providedOTP int32, fallbackOTP *int32, otpAbilities ...string) (*Token, error) {
	token, err := s.repo.FindByID(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	if !token.RequiresOTP() {
		return nil, ErrOTPRequired
	}

	if token.IsOTPExhausted() {
		return nil, ErrOTPExhausted
	}

	if len(otpAbilities) > 0 && !CanAll(token.Abilities, otpAbilities) {
		return nil, ErrOTPRequired
	}

	// Verify against primary OTP
	otpHash := HashOTP(providedOTP)
	isValid := otpHash == token.OTPHash

	// Try fallback OTP if primary doesn't match
	if !isValid && fallbackOTP != nil {
		fallbackHash := HashOTP(*fallbackOTP)
		isValid = fallbackHash == otpHash
	}

	if !isValid {
		// Increment attempts and check if exhausted
		token.OTPAttempts++
		token.UpdatedAt = time.Now()

		if err := s.repo.Update(ctx, token); err != nil {
			return nil, fmt.Errorf("sanctum: update token attempts: %w", err)
		}

		if token.IsOTPExhausted() {
			// Revoke the token automatically
			if err := s.repo.Revoke(ctx, tokenID); err != nil {
				return nil, fmt.Errorf("sanctum: revoke token after exhausted attempts: %w", err)
			}
			return nil, ErrOTPExhausted
		}

		return nil, ErrInvalidOTP
	}

	// OTP verified successfully — clear it from the token
	token.OTPHash = ""
	token.OTPAttempts = 0
	token.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, token); err != nil {
		return nil, fmt.Errorf("sanctum: clear OTP: %w", err)
	}

	return token, nil
}

// InvalidateOTP marks a token's OTP as no longer valid without clearing it.
// This can be used to require re-verification.
func (s *TokenService) InvalidateOTP(ctx context.Context, tokenID string) error {
	token, err := s.repo.FindByID(ctx, tokenID)
	if err != nil {
		return err
	}

	if !token.RequiresOTP() {
		return ErrOTPRequired
	}

	token.OTPAttempts = 0
	token.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, token); err != nil {
		return fmt.Errorf("sanctum: invalidate OTP: %w", err)
	}

	return nil
}
