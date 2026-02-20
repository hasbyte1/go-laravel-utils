package sanctum_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

// testUser is a minimal User implementation for tests.
type testUser struct{ id string }

func (u *testUser) GetID() string { return u.id }

// newTestService builds a TokenService backed by in-memory repositories and
// pre-populates the user store with the provided user IDs.
func newTestService(t testing.TB, userIDs ...string) (*sanctum.TokenService, *inmemory.Repository) {
	t.Helper()
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	for _, id := range userIDs {
		users.Add(&testUser{id: id})
	}
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	return svc, repo
}

func TestTokenService_CreateAndAuthenticate(t *testing.T) {
	svc, _ := newTestService(t, "user1")
	ctx := context.Background()

	result, err := svc.CreateToken(ctx, "user1", sanctum.CreateTokenOptions{Name: "test"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	user, token, err := svc.AuthenticateToken(ctx, result.PlainText, nil)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if user.GetID() != "user1" {
		t.Errorf("user ID = %q, want %q", user.GetID(), "user1")
	}
	if token.Name != "test" {
		t.Errorf("token.Name = %q", token.Name)
	}
}

func TestTokenService_DefaultAbilitiesIsWildcard(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})
	_, tok, _ := svc.AuthenticateToken(context.Background(), result.PlainText, nil)
	if len(tok.Abilities) != 1 || tok.Abilities[0] != "*" {
		t.Errorf("expected wildcard abilities, got %v", tok.Abilities)
	}
}

func TestTokenService_CustomAbilities(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"servers:read", "servers:write"},
	})
	_, tok, _ := svc.AuthenticateToken(context.Background(), result.PlainText, nil)
	if len(tok.Abilities) != 2 {
		t.Fatalf("expected 2 abilities, got %v", tok.Abilities)
	}
	if tok.Abilities[0] != "servers:read" || tok.Abilities[1] != "servers:write" {
		t.Errorf("abilities = %v", tok.Abilities)
	}
}

func TestTokenService_ExpiredToken(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	past := time.Now().Add(-time.Second)
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		ExpiresAt: &past,
	})

	_, _, err := svc.AuthenticateToken(context.Background(), result.PlainText, nil)
	if !errors.Is(err, sanctum.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestTokenService_DefaultExpiry(t *testing.T) {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&testUser{id: "u1"})
	cfg := sanctum.DefaultConfig()
	cfg.DefaultExpiry = 24 * time.Hour
	svc := sanctum.NewTokenService(repo, users, cfg)

	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})
	if result.Token.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set from DefaultExpiry")
	}
	if time.Until(*result.Token.ExpiresAt) < 23*time.Hour {
		t.Error("ExpiresAt is too soon")
	}
}

func TestTokenService_InvalidToken(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	_, _, err := svc.AuthenticateToken(context.Background(), "badtoken", nil)
	if err == nil {
		t.Fatal("expected error for non-existent token")
	}
}

func TestTokenService_WrongSecret(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})
	// Tamper with the secret part.
	id := result.Token.ID
	tampered := id + "|wrongsecret"
	_, _, err := svc.AuthenticateToken(context.Background(), tampered, nil)
	if !errors.Is(err, sanctum.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestTokenService_RevokeToken(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{})

	if err := svc.RevokeToken(context.Background(), result.Token.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	_, _, err := svc.AuthenticateToken(context.Background(), result.PlainText, nil)
	if !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Errorf("after revoke expected ErrTokenNotFound, got %v", err)
	}
}

func TestTokenService_RevokeAllTokens(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	r1, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{Name: "a"})
	r2, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{Name: "b"})

	if err := svc.RevokeAllTokens(ctx, "u1"); err != nil {
		t.Fatal(err)
	}

	for _, plain := range []string{r1.PlainText, r2.PlainText} {
		_, _, err := svc.AuthenticateToken(ctx, plain, nil)
		if !errors.Is(err, sanctum.ErrTokenNotFound) {
			t.Errorf("expected ErrTokenNotFound after RevokeAll, got %v", err)
		}
	}
}

func TestTokenService_ListTokens(t *testing.T) {
	svc, _ := newTestService(t, "u1", "u2")
	ctx := context.Background()

	svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{Name: "first"})
	svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{Name: "second"})
	svc.CreateToken(ctx, "u2", sanctum.CreateTokenOptions{Name: "other"})

	tokens, err := svc.ListTokens(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens for u1, got %d", len(tokens))
	}
}

func TestTokenService_PruneExpired(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	past := time.Now().Add(-time.Second)
	svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{ExpiresAt: &past, Name: "expired1"})
	svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{ExpiresAt: &past, Name: "expired2"})
	svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{Name: "live"}) // no expiry

	n, err := svc.PruneExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 pruned, got %d", n)
	}

	tokens, _ := svc.ListTokens(ctx, "u1")
	if len(tokens) != 1 {
		t.Errorf("expected 1 remaining token, got %d", len(tokens))
	}
}

func TestTokenService_AuthenticateUpdatesLastUsedAt(t *testing.T) {
	svc, repo := newTestService(t, "u1")
	ctx := context.Background()

	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{})
	tok, _ := repo.FindByID(ctx, result.Token.ID)
	if tok.LastUsedAt != nil {
		t.Error("LastUsedAt should be nil before first use")
	}

	svc.AuthenticateToken(ctx, result.PlainText, nil)

	tok, _ = repo.FindByID(ctx, result.Token.ID)
	if tok.LastUsedAt == nil {
		t.Error("LastUsedAt should be set after authentication")
	}
}

func TestTokenService_AuthenticateUpdatesUserIP(t *testing.T) {
	svc, repo := newTestService(t, "u1")
	ctx := context.Background()

	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{})
	tok, _ := repo.FindByID(ctx, result.Token.ID)
	if tok.UserIP != nil {
		t.Error("UserIP should be nil before first use")
	}

	userIP := "192.168.1.100"
	svc.AuthenticateToken(ctx, result.PlainText, &userIP)

	tok, _ = repo.FindByID(ctx, result.Token.ID)
	if tok.UserIP == nil || *tok.UserIP != userIP {
		t.Errorf("UserIP should be set to %q after authentication, got %v", userIP, tok.UserIP)
	}
}

func TestTokenService_RevokeNonExistent(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	err := svc.RevokeToken(context.Background(), "does-not-exist")
	if err == nil {
		t.Error("expected error revoking non-existent token")
	}
}

func TestTokenService_VerifyOTP_WithoutOptions(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name:      "otp-token",
		OTP:       &otp,
		Abilities: []string{"read", "write"},
	})

	// Verify OTP without options
	verified, err := svc.VerifyOTP(ctx, result.Token.ID, otp, nil, nil)
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}

	// Check that OTP was cleared
	if verified.OTPHash != "" {
		t.Error("OTPHash should be cleared after verification")
	}
	if verified.OTPAttempts != 0 {
		t.Error("OTPAttempts should be reset to 0")
	}

	// Check that abilities were not modified
	if len(verified.Abilities) != 2 || verified.Abilities[0] != "read" || verified.Abilities[1] != "write" {
		t.Errorf("Abilities should remain unchanged: %v", verified.Abilities)
	}
}

func TestTokenService_VerifyOTP_UpdateAbilities(t *testing.T) {
	svc, repo := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP and initial abilities
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name:      "otp-token",
		OTP:       &otp,
		Abilities: []string{"read"},
	})

	// Verify OTP with updated abilities
	verified, err := svc.VerifyOTP(ctx, result.Token.ID, otp, nil, &sanctum.VerifyOTPOptions{
		Abilities: []string{"read", "write", "delete"},
	})
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}

	// Check that abilities were updated
	if len(verified.Abilities) != 3 {
		t.Errorf("Expected 3 abilities, got %d", len(verified.Abilities))
	}
	if !sanctum.Can(verified.Abilities, "write") || !sanctum.Can(verified.Abilities, "delete") {
		t.Error("Token should have write and delete abilities after verification")
	}

	// Verify persisted
	persisted, _ := repo.FindByID(ctx, result.Token.ID)
	if len(persisted.Abilities) != 3 {
		t.Errorf("Persisted abilities should be updated, got %d", len(persisted.Abilities))
	}
}

func TestTokenService_VerifyOTP_UpdateActiveRole(t *testing.T) {
	svc, repo := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name: "otp-token",
		OTP:  &otp,
	})

	// Verify OTP with updated active role
	newRole := `{"id":"admin","permissions":["*"]}`
	verified, err := svc.VerifyOTP(ctx, result.Token.ID, otp, nil, &sanctum.VerifyOTPOptions{
		ActiveRole: &newRole,
	})
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}

	// Check that active role was updated
	if verified.ActiveRole == nil || *verified.ActiveRole != newRole {
		t.Errorf("ActiveRole should be updated to %q, got %v", newRole, verified.ActiveRole)
	}

	// Verify persisted
	persisted, _ := repo.FindByID(ctx, result.Token.ID)
	if persisted.ActiveRole == nil || *persisted.ActiveRole != newRole {
		t.Errorf("Persisted ActiveRole should be updated, got %v", persisted.ActiveRole)
	}
}

func TestTokenService_VerifyOTP_UpdateBothAbilitiesAndRole(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP and initial state
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name:      "otp-token",
		OTP:       &otp,
		Abilities: []string{"read"},
	})

	// Verify OTP with both abilities and role updates
	newAbilities := []string{"read", "write", "admin"}
	newRole := "manager"
	verified, err := svc.VerifyOTP(ctx, result.Token.ID, otp, nil, &sanctum.VerifyOTPOptions{
		Abilities:  newAbilities,
		ActiveRole: &newRole,
	})
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}

	// Check both were updated
	if len(verified.Abilities) != 3 {
		t.Errorf("Expected 3 abilities, got %d", len(verified.Abilities))
	}
	if verified.ActiveRole == nil || *verified.ActiveRole != newRole {
		t.Errorf("ActiveRole should be %q, got %v", newRole, verified.ActiveRole)
	}
}

func TestTokenService_VerifyOTP_RequiredAbilities(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP and specific abilities
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name:      "otp-token",
		OTP:       &otp,
		Abilities: []string{"read"},
	})

	// Try to verify with required ability that token doesn't have
	verified, err := svc.VerifyOTP(ctx, result.Token.ID, otp, nil, &sanctum.VerifyOTPOptions{
		RequiredAbilities: []string{"admin"},
	})
	if !errors.Is(err, sanctum.ErrOTPRequired) {
		t.Errorf("expected ErrOTPRequired for missing required ability, got %v", err)
	}
	if verified != nil {
		t.Error("verified should be nil when required ability check fails")
	}

	// Verify with required ability that token has
	verified, err = svc.VerifyOTP(ctx, result.Token.ID, otp, nil, &sanctum.VerifyOTPOptions{
		RequiredAbilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("VerifyOTP with matching required ability: %v", err)
	}
	if verified == nil {
		t.Error("verified should not be nil when required ability matches")
	}
}

func TestTokenService_VerifyOTP_RequiredAbilitiesWithUpdates(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name:      "otp-token",
		OTP:       &otp,
		Abilities: []string{"user:read", "user:write"},
	})

	// Verify with required abilities and update abilities
	newAbilities := []string{"admin:*"}
	verified, err := svc.VerifyOTP(ctx, result.Token.ID, otp, nil, &sanctum.VerifyOTPOptions{
		RequiredAbilities: []string{"user:read"},
		Abilities:         newAbilities,
	})
	if err != nil {
		t.Fatalf("VerifyOTP: %v", err)
	}

	// Check abilities were updated despite required check
	if len(verified.Abilities) != 1 || verified.Abilities[0] != "admin:*" {
		t.Errorf("Abilities should be updated to admin:*, got %v", verified.Abilities)
	}
}

func TestTokenService_IsValidToken_Valid(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{Name: "test"})

	// Token should be valid
	err := svc.IsValidToken(result.Token, false, false)
	if err != nil {
		t.Errorf("expected valid token, got error: %v", err)
	}
}

func TestTokenService_IsValidToken_Expired(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create token that expires immediately
	expires := time.Now().Add(-1 * time.Hour)
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name:      "expired",
		ExpiresAt: &expires,
	})

	// Token should be invalid due to expiration
	err := svc.IsValidToken(result.Token, false, false)
	if !errors.Is(err, sanctum.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestTokenService_IsValidToken_RequiresOTP(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP requirement
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name: "otp-token",
		OTP:  &otp,
	})

	// Token should be invalid when checking OTP requirement
	err := svc.IsValidToken(result.Token, true, false)
	if !errors.Is(err, sanctum.ErrOTPRequired) {
		t.Errorf("expected ErrOTPRequired, got %v", err)
	}

	// Token should be valid when not checking OTP requirement
	err = svc.IsValidToken(result.Token, false, false)
	if err != nil {
		t.Errorf("expected valid token when not checking OTP, got error: %v", err)
	}
}

func TestTokenService_IsValidToken_OTPExhausted(t *testing.T) {
	svc, repo := newTestService(t, "u1")
	ctx := context.Background()

	// Create token with OTP
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name: "otp-token",
		OTP:  &otp,
	})

	// Manually set OTP attempts to max
	token := result.Token
	token.OTPAttempts = 3
	repo.Update(ctx, token)

	// Token should be invalid when checking OTP exhaustion
	err := svc.IsValidToken(token, false, true)
	if !errors.Is(err, sanctum.ErrOTPExhausted) {
		t.Errorf("expected ErrOTPExhausted, got %v", err)
	}

	// Token should be valid when not checking OTP exhaustion
	err = svc.IsValidToken(token, false, false)
	if err != nil {
		t.Errorf("expected valid token when not checking OTP exhaustion, got error: %v", err)
	}
}

func TestTokenService_IsValidToken_MultipleChecks(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	ctx := context.Background()

	// Create non-expired token with OTP
	otp := "123456"
	result, _ := svc.CreateToken(ctx, "u1", sanctum.CreateTokenOptions{
		Name: "otp-token",
		OTP:  &otp,
	})

	// Should fail OTP check first
	err := svc.IsValidToken(result.Token, true, true)
	if !errors.Is(err, sanctum.ErrOTPRequired) {
		t.Errorf("expected ErrOTPRequired when both checks enabled, got %v", err)
	}
}
