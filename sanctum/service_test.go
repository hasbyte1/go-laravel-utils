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

	user, token, err := svc.AuthenticateToken(ctx, result.PlainText)
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
	_, tok, _ := svc.AuthenticateToken(context.Background(), result.PlainText)
	if len(tok.Abilities) != 1 || tok.Abilities[0] != "*" {
		t.Errorf("expected wildcard abilities, got %v", tok.Abilities)
	}
}

func TestTokenService_CustomAbilities(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	result, _ := svc.CreateToken(context.Background(), "u1", sanctum.CreateTokenOptions{
		Abilities: []string{"servers:read", "servers:write"},
	})
	_, tok, _ := svc.AuthenticateToken(context.Background(), result.PlainText)
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

	_, _, err := svc.AuthenticateToken(context.Background(), result.PlainText)
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
	_, _, err := svc.AuthenticateToken(context.Background(), "badtoken")
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
	_, _, err := svc.AuthenticateToken(context.Background(), tampered)
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

	_, _, err := svc.AuthenticateToken(context.Background(), result.PlainText)
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
		_, _, err := svc.AuthenticateToken(ctx, plain)
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

	svc.AuthenticateToken(ctx, result.PlainText)

	tok, _ = repo.FindByID(ctx, result.Token.ID)
	if tok.LastUsedAt == nil {
		t.Error("LastUsedAt should be set after authentication")
	}
}

func TestTokenService_RevokeNonExistent(t *testing.T) {
	svc, _ := newTestService(t, "u1")
	err := svc.RevokeToken(context.Background(), "does-not-exist")
	if err == nil {
		t.Error("expected error revoking non-existent token")
	}
}
