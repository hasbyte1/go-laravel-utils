package hashing_test

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hasbyte1/go-laravel-utils/hashing"
)

// ──────────────────────────────────────────────────────────────────────────────
// Bcrypt benchmarks
// ──────────────────────────────────────────────────────────────────────────────
//
// Note: bcrypt is intentionally slow.  BenchmarkBcrypt_Cost12 is the real-world
// cost; BenchmarkBcrypt_MinCost is included to measure framework overhead only.

func BenchmarkBcrypt_MinCost_Make(b *testing.B) {
	h, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: bcrypt.MinCost})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Make("bench-password")
	}
}

func BenchmarkBcrypt_MinCost_Check(b *testing.B) {
	h, _ := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: bcrypt.MinCost})
	hash, _ := h.Make("bench-password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Check("bench-password", hash)
	}
}

func BenchmarkBcrypt_Cost12_Make(b *testing.B) {
	h, _ := hashing.NewBcryptHasher(hashing.DefaultBcryptOptions())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Make("bench-password")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Argon2id benchmarks
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkArgon2id_Default_Make(b *testing.B) {
	h, _ := hashing.NewArgon2idHasher(hashing.DefaultArgon2Options())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Make("bench-password")
	}
}

func BenchmarkArgon2id_Default_Check(b *testing.B) {
	h, _ := hashing.NewArgon2idHasher(hashing.DefaultArgon2Options())
	hash, _ := h.Make("bench-password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Check("bench-password", hash)
	}
}

func BenchmarkArgon2id_Fast_Make(b *testing.B) {
	h, _ := hashing.NewArgon2idHasher(fastArgon2Opts())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Make("bench-password")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Argon2i benchmarks
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkArgon2i_Default_Make(b *testing.B) {
	h, _ := hashing.NewArgon2iHasher(hashing.DefaultArgon2Options())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Make("bench-password")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Manager benchmarks
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkManager_Make_Argon2id(b *testing.B) {
	m := newTestManager(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Make("bench-password")
	}
}

func BenchmarkManager_CheckWithDetect(b *testing.B) {
	m := newTestManager(b)
	hash, _ := m.Make("bench-password")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.CheckWithDetect("bench-password", hash)
	}
}

