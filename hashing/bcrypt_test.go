package hashing_test

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hasbyte1/go-laravel-utils/hashing"
)

// testBcryptCost is the minimum bcrypt work factor.  Used in unit tests only
// so the test suite runs quickly.  Production code should use DefaultBcryptCost.
const testBcryptCost = bcrypt.MinCost // 4

func newTestBcryptHasher(t *testing.T) *hashing.BcryptHasher {
	t.Helper()
	h, err := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: testBcryptCost})
	if err != nil {
		t.Fatalf("NewBcryptHasher: %v", err)
	}
	return h
}

// ──────────────────────────────────────────────────────────────────────────────
// Constructor
// ──────────────────────────────────────────────────────────────────────────────

func TestNewBcryptHasher_Valid(t *testing.T) {
	for _, cost := range []int{bcrypt.MinCost, 10, 12, bcrypt.MaxCost} {
		h, err := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: cost})
		if err != nil {
			t.Errorf("cost %d: unexpected error %v", cost, err)
		}
		if h == nil {
			t.Errorf("cost %d: expected non-nil hasher", cost)
		}
		if h != nil && h.Cost() != cost {
			t.Errorf("cost %d: got %d", cost, h.Cost())
		}
	}
}

func TestNewBcryptHasher_InvalidCost(t *testing.T) {
	cases := []int{bcrypt.MinCost - 1, 0, -1, bcrypt.MaxCost + 1, 99}
	for _, cost := range cases {
		_, err := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: cost})
		if !errors.Is(err, hashing.ErrInvalidOption) {
			t.Errorf("cost %d: expected ErrInvalidOption, got %v", cost, err)
		}
	}
}

func TestDefaultBcryptOptions(t *testing.T) {
	opts := hashing.DefaultBcryptOptions()
	if opts.Cost != hashing.DefaultBcryptCost {
		t.Errorf("got cost %d, want %d", opts.Cost, hashing.DefaultBcryptCost)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Make
// ──────────────────────────────────────────────────────────────────────────────

func TestBcryptHasher_Make_ReturnsHash(t *testing.T) {
	h := newTestBcryptHasher(t)
	hash, err := h.Make("password123")
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	if hash == "" {
		t.Fatal("Make returned empty hash")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash does not look like bcrypt: %q", hash)
	}
}

func TestBcryptHasher_Make_ProducesUniqueHashes(t *testing.T) {
	h := newTestBcryptHasher(t)
	h1, _ := h.Make("same-password")
	h2, _ := h.Make("same-password")
	if h1 == h2 {
		t.Error("two Make calls with the same password must produce different hashes (different salts)")
	}
}

func TestBcryptHasher_Make_EmptyPassword(t *testing.T) {
	h := newTestBcryptHasher(t)
	hash, err := h.Make("")
	if err != nil {
		t.Fatalf("Make empty password: %v", err)
	}
	ok, err := h.Check("", hash)
	if err != nil || !ok {
		t.Fatal("Check empty password failed")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Check
// ──────────────────────────────────────────────────────────────────────────────

func TestBcryptHasher_Check_CorrectPassword(t *testing.T) {
	h := newTestBcryptHasher(t)
	hash, _ := h.Make("hunter2")
	ok, err := h.Check("hunter2", hash)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !ok {
		t.Error("Check returned false for correct password")
	}
}

func TestBcryptHasher_Check_WrongPassword(t *testing.T) {
	h := newTestBcryptHasher(t)
	hash, _ := h.Make("hunter2")
	ok, err := h.Check("wrong-password", hash)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if ok {
		t.Error("Check returned true for wrong password")
	}
}

func TestBcryptHasher_Check_InvalidHash(t *testing.T) {
	h := newTestBcryptHasher(t)
	_, err := h.Check("password", "not-a-hash")
	if err == nil {
		t.Error("expected error for invalid hash format")
	}
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch, got %v", err)
	}
}

func TestBcryptHasher_Check_Argon2HashReturnsAlgorithmMismatch(t *testing.T) {
	h := newTestBcryptHasher(t)
	argon2Hash := "$argon2id$v=19$m=65536,t=3,p=2$abc$def"
	_, err := h.Check("password", argon2Hash)
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch for argon2 hash, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// NeedsRehash
// ──────────────────────────────────────────────────────────────────────────────

func TestBcryptHasher_NeedsRehash_SameCost(t *testing.T) {
	h := newTestBcryptHasher(t)
	hash, _ := h.Make("pw")
	needs, err := h.NeedsRehash(hash)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if needs {
		t.Error("NeedsRehash should be false when costs match")
	}
}

func TestBcryptHasher_NeedsRehash_DifferentCost(t *testing.T) {
	low, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: testBcryptCost})
	high, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: testBcryptCost + 1})

	// Hash with low cost, check against high-cost hasher.
	hash, _ := low.Make("pw")
	needs, err := high.NeedsRehash(hash)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if !needs {
		t.Error("NeedsRehash should be true when stored cost differs from configured cost")
	}
}

func TestBcryptHasher_NeedsRehash_InvalidHash(t *testing.T) {
	h := newTestBcryptHasher(t)
	_, err := h.NeedsRehash("not-a-hash")
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Info
// ──────────────────────────────────────────────────────────────────────────────

func TestBcryptHasher_Info(t *testing.T) {
	h := newTestBcryptHasher(t)
	hash, _ := h.Make("pw")
	info, err := h.Info(hash)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Driver != hashing.DriverBcrypt {
		t.Errorf("Driver = %q, want %q", info.Driver, hashing.DriverBcrypt)
	}
	cost, ok := info.Params["cost"].(int)
	if !ok {
		t.Fatalf("Params[\"cost\"] is not int: %T", info.Params["cost"])
	}
	if cost != testBcryptCost {
		t.Errorf("cost = %d, want %d", cost, testBcryptCost)
	}
}

func TestBcryptHasher_Info_InvalidHash(t *testing.T) {
	h := newTestBcryptHasher(t)
	_, err := h.Info("garbage")
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Driver
// ──────────────────────────────────────────────────────────────────────────────

func TestBcryptHasher_Driver(t *testing.T) {
	h := newTestBcryptHasher(t)
	if h.Driver() != hashing.DriverBcrypt {
		t.Errorf("got %q, want %q", h.Driver(), hashing.DriverBcrypt)
	}
}

func TestBcryptHasher_SatisfiesHasherInterface(t *testing.T) {
	h := newTestBcryptHasher(t)
	var _ hashing.Hasher = h
}
