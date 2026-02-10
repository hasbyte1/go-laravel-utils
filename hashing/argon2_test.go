package hashing_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/hashing"
)

// fastArgon2Opts returns minimal Argon2 parameters for unit tests.
// These are intentionally weak — do NOT use in production.
func fastArgon2Opts() hashing.Argon2Options {
	return hashing.Argon2Options{
		Memory:  8 * 2, // 8 × Threads minimum
		Time:    1,
		Threads: 2,
		KeyLen:  16,
		SaltLen: 8,
	}
}

func newTestArgon2iHasher(t *testing.T) *hashing.Argon2iHasher {
	t.Helper()
	h, err := hashing.NewArgon2iHasher(fastArgon2Opts())
	if err != nil {
		t.Fatalf("NewArgon2iHasher: %v", err)
	}
	return h
}

func newTestArgon2idHasher(t *testing.T) *hashing.Argon2idHasher {
	t.Helper()
	h, err := hashing.NewArgon2idHasher(fastArgon2Opts())
	if err != nil {
		t.Fatalf("NewArgon2idHasher: %v", err)
	}
	return h
}

// ──────────────────────────────────────────────────────────────────────────────
// Constructor validation
// ──────────────────────────────────────────────────────────────────────────────

func TestNewArgon2iHasher_InvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts hashing.Argon2Options
	}{
		{"time=0", hashing.Argon2Options{Memory: 64, Time: 0, Threads: 1, KeyLen: 16, SaltLen: 8}},
		{"threads=0", hashing.Argon2Options{Memory: 64, Time: 1, Threads: 0, KeyLen: 16, SaltLen: 8}},
		{"memory too low", hashing.Argon2Options{Memory: 1, Time: 1, Threads: 2, KeyLen: 16, SaltLen: 8}},
		{"key_len<4", hashing.Argon2Options{Memory: 64, Time: 1, Threads: 1, KeyLen: 3, SaltLen: 8}},
		{"salt_len<8", hashing.Argon2Options{Memory: 64, Time: 1, Threads: 1, KeyLen: 16, SaltLen: 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hashing.NewArgon2iHasher(tt.opts)
			if !errors.Is(err, hashing.ErrInvalidOption) {
				t.Errorf("expected ErrInvalidOption, got %v", err)
			}
		})
	}
}

func TestNewArgon2idHasher_InvalidOptions(t *testing.T) {
	// Mirror the same cases for argon2id.
	opts := hashing.Argon2Options{Memory: 1, Time: 0, Threads: 0, KeyLen: 1, SaltLen: 1}
	_, err := hashing.NewArgon2idHasher(opts)
	if !errors.Is(err, hashing.ErrInvalidOption) {
		t.Errorf("expected ErrInvalidOption, got %v", err)
	}
}

func TestDefaultArgon2Options(t *testing.T) {
	opts := hashing.DefaultArgon2Options()
	if opts.Memory != hashing.DefaultArgon2Memory {
		t.Errorf("Memory = %d, want %d", opts.Memory, hashing.DefaultArgon2Memory)
	}
	if opts.Time != hashing.DefaultArgon2Time {
		t.Errorf("Time = %d, want %d", opts.Time, hashing.DefaultArgon2Time)
	}
	if opts.Threads != hashing.DefaultArgon2Threads {
		t.Errorf("Threads = %d, want %d", opts.Threads, hashing.DefaultArgon2Threads)
	}
	if opts.KeyLen != hashing.DefaultArgon2KeyLen {
		t.Errorf("KeyLen = %d, want %d", opts.KeyLen, hashing.DefaultArgon2KeyLen)
	}
	if opts.SaltLen != hashing.DefaultArgon2SaltLen {
		t.Errorf("SaltLen = %d, want %d", opts.SaltLen, hashing.DefaultArgon2SaltLen)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Argon2i — Make / Check / NeedsRehash / Info
// ──────────────────────────────────────────────────────────────────────────────

func TestArgon2iHasher_Make_PHCFormat(t *testing.T) {
	h := newTestArgon2iHasher(t)
	hash, err := h.Make("password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2i$") {
		t.Errorf("hash should start with $argon2i$, got %q", hash)
	}
}

func TestArgon2iHasher_Make_UniqueHashes(t *testing.T) {
	h := newTestArgon2iHasher(t)
	h1, _ := h.Make("same")
	h2, _ := h.Make("same")
	if h1 == h2 {
		t.Error("two Make calls must produce different hashes (different salts)")
	}
}

func TestArgon2iHasher_Check_CorrectPassword(t *testing.T) {
	h := newTestArgon2iHasher(t)
	hash, _ := h.Make("secret")
	ok, err := h.Check("secret", hash)
	if err != nil || !ok {
		t.Fatalf("Check correct password: ok=%v err=%v", ok, err)
	}
}

func TestArgon2iHasher_Check_WrongPassword(t *testing.T) {
	h := newTestArgon2iHasher(t)
	hash, _ := h.Make("correct")
	ok, err := h.Check("wrong", hash)
	if err != nil {
		t.Fatalf("Check: unexpected error %v", err)
	}
	if ok {
		t.Error("Check returned true for wrong password")
	}
}

func TestArgon2iHasher_Check_EmptyPassword(t *testing.T) {
	h := newTestArgon2iHasher(t)
	hash, _ := h.Make("")
	ok, err := h.Check("", hash)
	if err != nil || !ok {
		t.Fatalf("empty password round-trip: ok=%v err=%v", ok, err)
	}
}

func TestArgon2iHasher_Check_InvalidHash(t *testing.T) {
	h := newTestArgon2iHasher(t)
	_, err := h.Check("pw", "not-a-hash")
	if !errors.Is(err, hashing.ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

func TestArgon2iHasher_Check_WrongVariant(t *testing.T) {
	h := newTestArgon2iHasher(t)
	// argon2id hash passed to argon2i hasher
	idH := newTestArgon2idHasher(t)
	hash, _ := idH.Make("pw")
	_, err := h.Check("pw", hash)
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch, got %v", err)
	}
}

func TestArgon2iHasher_NeedsRehash_SameParams(t *testing.T) {
	h := newTestArgon2iHasher(t)
	hash, _ := h.Make("pw")
	needs, err := h.NeedsRehash(hash)
	if err != nil || needs {
		t.Errorf("NeedsRehash same params: needs=%v err=%v", needs, err)
	}
}

func TestArgon2iHasher_NeedsRehash_DifferentMemory(t *testing.T) {
	opts := fastArgon2Opts()
	h1, _ := hashing.NewArgon2iHasher(opts)
	opts.Memory *= 2
	h2, _ := hashing.NewArgon2iHasher(opts)

	hash, _ := h1.Make("pw")
	needs, err := h2.NeedsRehash(hash)
	if err != nil || !needs {
		t.Errorf("expected NeedsRehash=true when memory differs: needs=%v err=%v", needs, err)
	}
}

func TestArgon2iHasher_Info(t *testing.T) {
	h := newTestArgon2iHasher(t)
	hash, _ := h.Make("pw")
	info, err := h.Info(hash)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Driver != hashing.DriverArgon2i {
		t.Errorf("Driver = %q, want %q", info.Driver, hashing.DriverArgon2i)
	}
	opts := fastArgon2Opts()
	if got := info.Params["memory"].(uint32); got != opts.Memory {
		t.Errorf("memory = %d, want %d", got, opts.Memory)
	}
	if got := info.Params["time"].(uint32); got != opts.Time {
		t.Errorf("time = %d, want %d", got, opts.Time)
	}
}

func TestArgon2iHasher_Driver(t *testing.T) {
	h := newTestArgon2iHasher(t)
	if h.Driver() != hashing.DriverArgon2i {
		t.Errorf("got %q, want %q", h.Driver(), hashing.DriverArgon2i)
	}
}

func TestArgon2iHasher_SatisfiesHasherInterface(t *testing.T) {
	h := newTestArgon2iHasher(t)
	var _ hashing.Hasher = h
}

// ──────────────────────────────────────────────────────────────────────────────
// Argon2id — Make / Check / NeedsRehash / Info
// ──────────────────────────────────────────────────────────────────────────────

func TestArgon2idHasher_Make_PHCFormat(t *testing.T) {
	h := newTestArgon2idHasher(t)
	hash, err := h.Make("password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should start with $argon2id$, got %q", hash)
	}
}

func TestArgon2idHasher_Make_UniqueHashes(t *testing.T) {
	h := newTestArgon2idHasher(t)
	h1, _ := h.Make("same")
	h2, _ := h.Make("same")
	if h1 == h2 {
		t.Error("two Make calls must produce different hashes")
	}
}

func TestArgon2idHasher_Check_CorrectPassword(t *testing.T) {
	h := newTestArgon2idHasher(t)
	hash, _ := h.Make("secure-pass")
	ok, err := h.Check("secure-pass", hash)
	if err != nil || !ok {
		t.Fatalf("Check correct password: ok=%v err=%v", ok, err)
	}
}

func TestArgon2idHasher_Check_WrongPassword(t *testing.T) {
	h := newTestArgon2idHasher(t)
	hash, _ := h.Make("correct")
	ok, err := h.Check("incorrect", hash)
	if err != nil || ok {
		t.Fatalf("Check wrong password: ok=%v err=%v", ok, err)
	}
}

func TestArgon2idHasher_Check_EmptyPassword(t *testing.T) {
	h := newTestArgon2idHasher(t)
	hash, _ := h.Make("")
	ok, _ := h.Check("", hash)
	if !ok {
		t.Error("empty password round-trip failed")
	}
}

func TestArgon2idHasher_Check_WrongVariant(t *testing.T) {
	h := newTestArgon2idHasher(t)
	iH := newTestArgon2iHasher(t)
	hash, _ := iH.Make("pw")
	_, err := h.Check("pw", hash)
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch, got %v", err)
	}
}

func TestArgon2idHasher_NeedsRehash_SameParams(t *testing.T) {
	h := newTestArgon2idHasher(t)
	hash, _ := h.Make("pw")
	needs, err := h.NeedsRehash(hash)
	if err != nil || needs {
		t.Errorf("NeedsRehash same params: needs=%v err=%v", needs, err)
	}
}

func TestArgon2idHasher_NeedsRehash_DifferentTime(t *testing.T) {
	opts := fastArgon2Opts()
	h1, _ := hashing.NewArgon2idHasher(opts)
	opts.Time++
	h2, _ := hashing.NewArgon2idHasher(opts)

	hash, _ := h1.Make("pw")
	needs, err := h2.NeedsRehash(hash)
	if err != nil || !needs {
		t.Errorf("expected NeedsRehash=true when time differs: needs=%v err=%v", needs, err)
	}
}

func TestArgon2idHasher_NeedsRehash_DifferentKeyLen(t *testing.T) {
	opts := fastArgon2Opts()
	h1, _ := hashing.NewArgon2idHasher(opts)
	opts.KeyLen = 32
	h2, _ := hashing.NewArgon2idHasher(opts)

	hash, _ := h1.Make("pw")
	needs, err := h2.NeedsRehash(hash)
	if err != nil || !needs {
		t.Errorf("expected NeedsRehash=true when key_len differs: needs=%v err=%v", needs, err)
	}
}

func TestArgon2idHasher_Info(t *testing.T) {
	h := newTestArgon2idHasher(t)
	hash, _ := h.Make("pw")
	info, err := h.Info(hash)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Driver != hashing.DriverArgon2id {
		t.Errorf("Driver = %q, want %q", info.Driver, hashing.DriverArgon2id)
	}
	opts := fastArgon2Opts()
	if got := info.Params["threads"].(uint8); got != opts.Threads {
		t.Errorf("threads = %d, want %d", got, opts.Threads)
	}
}

func TestArgon2idHasher_Info_WrongVariant(t *testing.T) {
	h := newTestArgon2idHasher(t)
	iH := newTestArgon2iHasher(t)
	hash, _ := iH.Make("pw")
	_, err := h.Info(hash)
	if !errors.Is(err, hashing.ErrAlgorithmMismatch) {
		t.Errorf("expected ErrAlgorithmMismatch, got %v", err)
	}
}

func TestArgon2idHasher_Driver(t *testing.T) {
	h := newTestArgon2idHasher(t)
	if h.Driver() != hashing.DriverArgon2id {
		t.Errorf("got %q, want %q", h.Driver(), hashing.DriverArgon2id)
	}
}

func TestArgon2idHasher_SatisfiesHasherInterface(t *testing.T) {
	h := newTestArgon2idHasher(t)
	var _ hashing.Hasher = h
}

// ──────────────────────────────────────────────────────────────────────────────
// PHC round-trip / interoperability
// ──────────────────────────────────────────────────────────────────────────────

// TestArgon2_PHCRoundTrip verifies that a hash produced with arbitrary (but
// valid) options can be verified by a hasher with different options — simulating
// what happens when you increase work factors between deployments.
func TestArgon2id_PHCRoundTrip_DifferentOptions(t *testing.T) {
	optsA := fastArgon2Opts()
	optsB := fastArgon2Opts()
	optsB.Memory *= 4
	optsB.Time = 2

	hA, _ := hashing.NewArgon2idHasher(optsA)
	hB, _ := hashing.NewArgon2idHasher(optsB)

	hash, _ := hA.Make("hello")

	// hB must still be able to verify the old hash (reads params from the hash itself).
	ok, err := hB.Check("hello", hash)
	if err != nil || !ok {
		t.Fatalf("cross-option Check failed: ok=%v err=%v", ok, err)
	}

	// And NeedsRehash should return true.
	needs, err := hB.NeedsRehash(hash)
	if err != nil || !needs {
		t.Fatalf("NeedsRehash after option upgrade: needs=%v err=%v", needs, err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// DetectDriver
// ──────────────────────────────────────────────────────────────────────────────

func TestDetectDriver(t *testing.T) {
	iH := newTestArgon2iHasher(t)
	idH := newTestArgon2idHasher(t)
	bcH := newTestBcryptHasher(t)

	hashI, _ := iH.Make("pw")
	hashID, _ := idH.Make("pw")
	hashBC, _ := bcH.Make("pw")

	tests := []struct {
		hash string
		want hashing.DriverName
	}{
		{hashI, hashing.DriverArgon2i},
		{hashID, hashing.DriverArgon2id},
		{hashBC, hashing.DriverBcrypt},
	}
	for _, tt := range tests {
		got, ok := hashing.DetectDriver(tt.hash)
		if !ok || got != tt.want {
			t.Errorf("DetectDriver(%q...) = (%q, %v), want (%q, true)", tt.hash[:10], got, ok, tt.want)
		}
	}
}

func TestDetectDriver_Unknown(t *testing.T) {
	_, ok := hashing.DetectDriver("some-random-string")
	if ok {
		t.Error("expected ok=false for unknown hash format")
	}
}
