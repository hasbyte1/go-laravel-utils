package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/hasbyte1/go-laravel-utils/passport"
)

type ephemeralEntry struct {
	value     []byte
	expiresAt time.Time // zero means no expiry
}

type ephemeralKV struct {
	mu      sync.RWMutex
	entries map[string]ephemeralEntry
}

// NewEphemeralKV returns a thread-safe in-memory passport.EphemeralKV.
// Intended for tests and single-instance development environments.
func NewEphemeralKV() passport.EphemeralKV {
	return &ephemeralKV{entries: make(map[string]ephemeralEntry)}
}

func (e *ephemeralKV) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	v := make([]byte, len(value))
	copy(v, value)
	e.mu.Lock()
	e.entries[key] = ephemeralEntry{value: v, expiresAt: exp}
	e.mu.Unlock()
	return nil
}

func (e *ephemeralKV) Get(_ context.Context, key string) ([]byte, error) {
	e.mu.RLock()
	entry, ok := e.entries[key]
	e.mu.RUnlock()
	if !ok {
		return nil, passport.ErrKeyNotFound
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		e.mu.Lock()
		delete(e.entries, key)
		e.mu.Unlock()
		return nil, passport.ErrKeyNotFound
	}
	v := make([]byte, len(entry.value))
	copy(v, entry.value)
	return v, nil
}

func (e *ephemeralKV) Delete(_ context.Context, key string) error {
	e.mu.Lock()
	delete(e.entries, key)
	e.mu.Unlock()
	return nil
}
