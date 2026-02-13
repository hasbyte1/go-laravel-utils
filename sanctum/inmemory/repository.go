// Package inmemory provides a thread-safe in-memory implementation of
// [sanctum.TokenRepository] and [sanctum.UserProvider].
//
// It is intended for use in tests and prototyping. Do not use it in production.
package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
)

// Repository is a thread-safe in-memory implementation of [sanctum.TokenRepository].
type Repository struct {
	mu     sync.RWMutex
	tokens map[string]*sanctum.Token // keyed by token ID
}

// New creates an empty [Repository].
func New() *Repository {
	return &Repository{tokens: make(map[string]*sanctum.Token)}
}

// Create stores a new token. Returns an error when a token with the same ID already exists.
func (r *Repository) Create(_ context.Context, token *sanctum.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tokens[token.ID]; exists {
		return &duplicateIDError{id: token.ID}
	}
	r.tokens[token.ID] = cloneToken(token)
	return nil
}

// FindByID retrieves a token by its UUID. Returns [sanctum.ErrTokenNotFound] when absent.
func (r *Repository) FindByID(_ context.Context, id string) (*sanctum.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tokens[id]
	if !ok {
		return nil, sanctum.ErrTokenNotFound
	}
	return cloneToken(t), nil
}

// FindByHash retrieves a token by its SHA-256 secret hash. Returns [sanctum.ErrTokenNotFound]
// when no matching token exists.
func (r *Repository) FindByHash(_ context.Context, hash string) (*sanctum.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, t := range r.tokens {
		if t.Hash == hash {
			return cloneToken(t), nil
		}
	}
	return nil, sanctum.ErrTokenNotFound
}

// UpdateLastUsedAt records the time a token was most recently authenticated.
func (r *Repository) UpdateLastUsedAt(_ context.Context, id string, t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	tok, ok := r.tokens[id]
	if !ok {
		return sanctum.ErrTokenNotFound
	}
	tok.LastUsedAt = &t
	tok.UpdatedAt = t
	return nil
}

// Update persists changes to an existing token.
func (r *Repository) Update(_ context.Context, token *sanctum.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.tokens[token.ID]; !ok {
		return sanctum.ErrTokenNotFound
	}
	r.tokens[token.ID] = cloneToken(token)
	return nil
}

// Revoke removes the token with the given ID. Returns [sanctum.ErrTokenNotFound] when absent.
func (r *Repository) Revoke(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.tokens[id]; !ok {
		return sanctum.ErrTokenNotFound
	}
	delete(r.tokens, id)
	return nil
}

// RevokeAll removes all tokens belonging to the specified user.
func (r *Repository) RevokeAll(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, t := range r.tokens {
		if t.UserID == userID {
			delete(r.tokens, id)
		}
	}
	return nil
}

// ListByUser returns all tokens owned by the specified user.
func (r *Repository) ListByUser(_ context.Context, userID string) ([]*sanctum.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*sanctum.Token
	for _, t := range r.tokens {
		if t.UserID == userID {
			out = append(out, cloneToken(t))
		}
	}
	return out, nil
}

// PruneExpired deletes all expired tokens and returns the number removed.
func (r *Repository) PruneExpired(_ context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var n int64
	for id, t := range r.tokens {
		if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
			delete(r.tokens, id)
			n++
		}
	}
	return n, nil
}

// cloneToken returns a shallow copy of t with its Abilities slice deep-copied.
func cloneToken(t *sanctum.Token) *sanctum.Token {
	cp := *t
	if t.Abilities != nil {
		cp.Abilities = make([]string, len(t.Abilities))
		copy(cp.Abilities, t.Abilities)
	}
	return &cp
}

type duplicateIDError struct{ id string }

func (e *duplicateIDError) Error() string {
	return "sanctum/inmemory: duplicate token ID: " + e.id
}

// UserStore is a thread-safe in-memory implementation of [sanctum.UserProvider].
type UserStore struct {
	mu    sync.RWMutex
	users map[string]sanctum.User // keyed by user ID
}

// NewUserStore creates an empty [UserStore].
func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]sanctum.User)}
}

// Add registers a user in the store. Overwrites any existing user with the same ID.
func (s *UserStore) Add(u sanctum.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.GetID()] = u
}

// FindByID implements [sanctum.UserProvider].
func (s *UserStore) FindByID(_ context.Context, id string) (sanctum.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}
