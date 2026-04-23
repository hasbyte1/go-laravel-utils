package passportredis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hasbyte1/go-laravel-utils/passport"
	"github.com/hasbyte1/go-laravel-utils/passport/passportredis"
)

func newTestKV(t *testing.T, prefix string) (passport.EphemeralKV, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return passportredis.NewEphemeralKV(client, prefix), mr
}

func TestEphemeralKV_SetGet(t *testing.T) {
	kv, _ := newTestKV(t, "test:")
	ctx := context.Background()

	if err := kv.Set(ctx, "k", []byte("hello"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := kv.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestEphemeralKV_MissReturnsErrKeyNotFound(t *testing.T) {
	kv, _ := newTestKV(t, "test:")
	_, err := kv.Get(context.Background(), "missing")
	if !errors.Is(err, passport.ErrKeyNotFound) {
		t.Fatalf("got %v, want passport.ErrKeyNotFound", err)
	}
}

func TestEphemeralKV_Delete(t *testing.T) {
	kv, _ := newTestKV(t, "test:")
	ctx := context.Background()
	_ = kv.Set(ctx, "k", []byte("v"), 0)
	_ = kv.Delete(ctx, "k")
	_, err := kv.Get(ctx, "k")
	if !errors.Is(err, passport.ErrKeyNotFound) {
		t.Fatalf("after delete got %v, want ErrKeyNotFound", err)
	}
}

func TestEphemeralKV_TTLExpiry(t *testing.T) {
	kv, mr := newTestKV(t, "test:")
	ctx := context.Background()
	_ = kv.Set(ctx, "k", []byte("v"), 5*time.Second)
	mr.FastForward(10 * time.Second)
	_, err := kv.Get(ctx, "k")
	if !errors.Is(err, passport.ErrKeyNotFound) {
		t.Fatalf("after TTL expiry got %v, want ErrKeyNotFound", err)
	}
}

func TestEphemeralKV_ZeroTTLPersists(t *testing.T) {
	kv, mr := newTestKV(t, "test:")
	ctx := context.Background()
	_ = kv.Set(ctx, "k", []byte("v"), 0)
	mr.FastForward(24 * time.Hour)
	if _, err := kv.Get(ctx, "k"); err != nil {
		t.Fatalf("zero TTL entry expired: %v", err)
	}
}

func TestEphemeralKV_KeyPrefix(t *testing.T) {
	kv1, _ := newTestKV(t, "a:")
	kv2, _ := newTestKV(t, "b:")
	ctx := context.Background()
	_ = kv1.Set(ctx, "k", []byte("from-a"), 0)
	_ = kv2.Set(ctx, "k", []byte("from-b"), 0)
	v1, _ := kv1.Get(ctx, "k")
	v2, _ := kv2.Get(ctx, "k")
	if string(v1) != "from-a" || string(v2) != "from-b" {
		t.Fatalf("prefix isolation failed: v1=%q v2=%q", v1, v2)
	}
}
