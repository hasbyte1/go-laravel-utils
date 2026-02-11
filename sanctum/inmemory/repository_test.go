package inmemory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

type testUser struct{ id string }

func (u *testUser) GetID() string { return u.id }

func makeToken(id, userID string) *sanctum.Token {
	return &sanctum.Token{
		ID:        id,
		UserID:    userID,
		Name:      "test",
		Hash:      sanctum.HashToken("secret-" + id),
		Abilities: []string{"*"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestRepository_CreateAndFindByID(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	tok := makeToken("id1", "u1")

	if err := r.Create(ctx, tok); err != nil {
		t.Fatal(err)
	}

	got, err := r.FindByID(ctx, "id1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "id1" || got.UserID != "u1" {
		t.Errorf("unexpected token: %+v", got)
	}
}

func TestRepository_Create_DuplicateID(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	tok := makeToken("dup", "u1")
	r.Create(ctx, tok)
	if err := r.Create(ctx, tok); err == nil {
		t.Error("expected error on duplicate ID")
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r := inmemory.New()
	_, err := r.FindByID(context.Background(), "missing")
	if !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestRepository_FindByHash(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	tok := makeToken("id2", "u1")
	r.Create(ctx, tok)

	got, err := r.FindByHash(ctx, tok.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "id2" {
		t.Errorf("wrong token ID: %q", got.ID)
	}
}

func TestRepository_FindByHash_NotFound(t *testing.T) {
	r := inmemory.New()
	_, err := r.FindByHash(context.Background(), "nohash")
	if !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestRepository_UpdateLastUsedAt(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	tok := makeToken("id3", "u1")
	r.Create(ctx, tok)

	now := time.Now()
	if err := r.UpdateLastUsedAt(ctx, "id3", now); err != nil {
		t.Fatal(err)
	}

	got, _ := r.FindByID(ctx, "id3")
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt not set")
	}
	if !got.LastUsedAt.Equal(now) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, now)
	}
}

func TestRepository_Revoke(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	tok := makeToken("id4", "u1")
	r.Create(ctx, tok)

	if err := r.Revoke(ctx, "id4"); err != nil {
		t.Fatal(err)
	}
	_, err := r.FindByID(ctx, "id4")
	if !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound after revoke, got %v", err)
	}
}

func TestRepository_Revoke_NotFound(t *testing.T) {
	r := inmemory.New()
	err := r.Revoke(context.Background(), "missing")
	if !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestRepository_RevokeAll(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	r.Create(ctx, makeToken("a", "u1"))
	r.Create(ctx, makeToken("b", "u1"))
	r.Create(ctx, makeToken("c", "u2"))

	r.RevokeAll(ctx, "u1")

	if _, err := r.FindByID(ctx, "a"); !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Error("token a should be revoked")
	}
	if _, err := r.FindByID(ctx, "b"); !errors.Is(err, sanctum.ErrTokenNotFound) {
		t.Error("token b should be revoked")
	}
	if _, err := r.FindByID(ctx, "c"); err != nil {
		t.Error("token c (u2) should still exist")
	}
}

func TestRepository_ListByUser(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	r.Create(ctx, makeToken("x1", "u1"))
	r.Create(ctx, makeToken("x2", "u1"))
	r.Create(ctx, makeToken("x3", "u2"))

	tokens, err := r.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Errorf("expected 2, got %d", len(tokens))
	}
}

func TestRepository_PruneExpired(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()

	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)

	expired1 := makeToken("e1", "u1")
	expired1.ExpiresAt = &past
	expired2 := makeToken("e2", "u1")
	expired2.ExpiresAt = &past
	live := makeToken("live", "u1")
	live.ExpiresAt = &future

	r.Create(ctx, expired1)
	r.Create(ctx, expired2)
	r.Create(ctx, live)

	n, err := r.PruneExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 pruned, got %d", n)
	}

	remaining, _ := r.ListByUser(ctx, "u1")
	if len(remaining) != 1 || remaining[0].ID != "live" {
		t.Errorf("unexpected remaining: %+v", remaining)
	}
}

func TestRepository_CloneOnCreate(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()
	tok := makeToken("iso", "u1")
	r.Create(ctx, tok)

	// Mutating the original should not affect the stored copy.
	tok.Name = "mutated"
	got, _ := r.FindByID(ctx, "iso")
	if got.Name == "mutated" {
		t.Error("repository should store an independent copy")
	}
}

func TestRepository_Concurrent(t *testing.T) {
	r := inmemory.New()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("tok-%d", n)
			r.Create(ctx, makeToken(id, "u1"))
			r.FindByID(ctx, id)
			r.UpdateLastUsedAt(ctx, id, time.Now())
		}(i)
	}
	wg.Wait()
}

func TestUserStore_AddAndFind(t *testing.T) {
	s := inmemory.NewUserStore()
	u := &testUser{id: "u99"}
	s.Add(u)

	got, err := s.FindByID(context.Background(), "u99")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.GetID() != "u99" {
		t.Errorf("unexpected user: %v", got)
	}
}

func TestUserStore_FindByID_NotFound(t *testing.T) {
	s := inmemory.NewUserStore()
	got, err := s.FindByID(context.Background(), "missing")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected nil user for missing ID")
	}
}
