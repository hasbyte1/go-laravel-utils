package inmemory_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hasbyte1/go-laravel-utils/passport"
	"github.com/hasbyte1/go-laravel-utils/passport/inmemory"
)

func TestEphemeralKV_SetGet(t *testing.T) {
	kv := inmemory.NewEphemeralKV()
	ctx := context.Background()

	if err := kv.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := kv.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("got %q, want %q", got, "v")
	}
}

func TestEphemeralKV_MissReturnsErrKeyNotFound(t *testing.T) {
	kv := inmemory.NewEphemeralKV()
	_, err := kv.Get(context.Background(), "missing")
	if !errors.Is(err, passport.ErrKeyNotFound) {
		t.Fatalf("got %v, want passport.ErrKeyNotFound", err)
	}
}

func TestEphemeralKV_Delete(t *testing.T) {
	kv := inmemory.NewEphemeralKV()
	ctx := context.Background()
	_ = kv.Set(ctx, "k", []byte("v"), 0)
	_ = kv.Delete(ctx, "k")
	_, err := kv.Get(ctx, "k")
	if !errors.Is(err, passport.ErrKeyNotFound) {
		t.Fatalf("after delete got %v, want ErrKeyNotFound", err)
	}
}

func TestEphemeralKV_TTLExpiry(t *testing.T) {
	kv := inmemory.NewEphemeralKV()
	ctx := context.Background()
	_ = kv.Set(ctx, "k", []byte("v"), 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	_, err := kv.Get(ctx, "k")
	if !errors.Is(err, passport.ErrKeyNotFound) {
		t.Fatalf("after TTL expiry got %v, want ErrKeyNotFound", err)
	}
}

func TestEphemeralKV_ZeroTTLNeverExpires(t *testing.T) {
	kv := inmemory.NewEphemeralKV()
	ctx := context.Background()
	_ = kv.Set(ctx, "k", []byte("v"), 0)
	time.Sleep(10 * time.Millisecond)
	if _, err := kv.Get(ctx, "k"); err != nil {
		t.Fatalf("zero TTL entry expired unexpectedly: %v", err)
	}
}

func TestEphemeralKV_ConcurrentAccess(t *testing.T) {
	kv := inmemory.NewEphemeralKV()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i)
			_ = kv.Set(ctx, key, []byte("v"), 0)
			_, _ = kv.Get(ctx, key)
			_ = kv.Delete(ctx, key)
		}(i)
	}
	wg.Wait()
}
