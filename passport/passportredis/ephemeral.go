// Package passportredis provides a Redis-backed EphemeralKV for the passport package.
// Import this package to use Redis for PKCE sessions, OIDC sessions, JTI denylist,
// and device session state instead of the default in-memory maps.
package passportredis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/hasbyte1/go-laravel-utils/passport"
)

type ephemeralKV struct {
	client    *goredis.Client
	keyPrefix string
}

// NewEphemeralKV returns a Redis-backed passport.EphemeralKV.
// keyPrefix is prepended to every key (e.g. "pkce:", "oidc:").
// Use distinct prefixes for each of the four stores to avoid key collisions.
func NewEphemeralKV(client *goredis.Client, keyPrefix string) passport.EphemeralKV {
	return &ephemeralKV{client: client, keyPrefix: keyPrefix}
}

func (e *ephemeralKV) k(key string) string { return e.keyPrefix + key }

func (e *ephemeralKV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := e.client.Set(ctx, e.k(key), value, ttl).Err(); err != nil {
		return fmt.Errorf("passportredis: set %q: %w", key, err)
	}
	return nil
}

func (e *ephemeralKV) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := e.client.Get(ctx, e.k(key)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, passport.ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("passportredis: get %q: %w", key, err)
	}
	return val, nil
}

func (e *ephemeralKV) Delete(ctx context.Context, key string) error {
	if err := e.client.Del(ctx, e.k(key)).Err(); err != nil {
		return fmt.Errorf("passportredis: delete %q: %w", key, err)
	}
	return nil
}
