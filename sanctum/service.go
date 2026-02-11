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

	result, err := generateToken(userID, opts.Name, abilities, expiresAt)
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
//
// LastUsedAt is updated as a best-effort side effect; auth is not failed if the
// update itself errors.
func (s *TokenService) AuthenticateToken(ctx context.Context, plainText string) (User, *Token, error) {
	id, secret, err := parseTokenID(plainText)
	if err != nil {
		// No valid ID prefix — fall back to full-string hash lookup.
		hash := HashToken(plainText)
		return s.authenticateByHash(ctx, hash)
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

	user, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("sanctum: load user: %w", err)
	}
	if user == nil {
		return nil, nil, ErrTokenNotFound
	}

	_ = s.repo.UpdateLastUsedAt(ctx, token.ID, time.Now())
	return user, token, nil
}

func (s *TokenService) authenticateByHash(ctx context.Context, hash string) (User, *Token, error) {
	token, err := s.repo.FindByHash(ctx, hash)
	if err != nil {
		return nil, nil, err
	}

	if token.IsExpired() {
		return nil, nil, ErrTokenExpired
	}

	user, err := s.users.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("sanctum: load user: %w", err)
	}
	if user == nil {
		return nil, nil, ErrTokenNotFound
	}

	_ = s.repo.UpdateLastUsedAt(ctx, token.ID, time.Now())
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
