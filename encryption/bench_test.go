package encryption_test

import (
	"bytes"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/encryption"
)

// ──────────────────────────────────────────────────────────────────────────────
// AES-256-CBC benchmarks
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkCBCEncrypt_1KB(b *testing.B) {
	benchmarkCBCEncrypt(b, 1<<10)
}

func BenchmarkCBCEncrypt_64KB(b *testing.B) {
	benchmarkCBCEncrypt(b, 64<<10)
}

func BenchmarkCBCEncrypt_1MB(b *testing.B) {
	benchmarkCBCEncrypt(b, 1<<20)
}

func BenchmarkCBCDecrypt_1KB(b *testing.B) {
	benchmarkCBCDecrypt(b, 1<<10)
}

func BenchmarkCBCDecrypt_64KB(b *testing.B) {
	benchmarkCBCDecrypt(b, 64<<10)
}

func BenchmarkCBCDecrypt_1MB(b *testing.B) {
	benchmarkCBCDecrypt(b, 1<<20)
}

// ──────────────────────────────────────────────────────────────────────────────
// AES-256-GCM benchmarks
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkGCMEncrypt_1KB(b *testing.B) {
	benchmarkGCMEncrypt(b, 1<<10)
}

func BenchmarkGCMEncrypt_64KB(b *testing.B) {
	benchmarkGCMEncrypt(b, 64<<10)
}

func BenchmarkGCMEncrypt_1MB(b *testing.B) {
	benchmarkGCMEncrypt(b, 1<<20)
}

func BenchmarkGCMDecrypt_1KB(b *testing.B) {
	benchmarkGCMDecrypt(b, 1<<10)
}

func BenchmarkGCMDecrypt_64KB(b *testing.B) {
	benchmarkGCMDecrypt(b, 64<<10)
}

func BenchmarkGCMDecrypt_1MB(b *testing.B) {
	benchmarkGCMDecrypt(b, 1<<20)
}

// ──────────────────────────────────────────────────────────────────────────────
// Key generation benchmark
// ──────────────────────────────────────────────────────────────────────────────

func BenchmarkGenerateKey_AES256CBC(b *testing.B) {
	b.ReportAllocs()
	for b.N > 0 {
		b.N--
		_, err := encryption.GenerateKey(encryption.AES256CBC)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func benchmarkCBCEncrypt(b *testing.B, size int) {
	b.Helper()
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)
	plaintext := bytes.Repeat([]byte("x"), size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encrypt(plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkCBCDecrypt(b *testing.B, size int) {
	b.Helper()
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)
	plaintext := bytes.Repeat([]byte("x"), size)
	ciphertext, _ := enc.Encrypt(plaintext)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Decrypt(ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkGCMEncrypt(b *testing.B, size int) {
	b.Helper()
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
	plaintext := bytes.Repeat([]byte("x"), size)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encrypt(plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkGCMDecrypt(b *testing.B, size int) {
	b.Helper()
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
	plaintext := bytes.Repeat([]byte("x"), size)
	ciphertext, _ := enc.Encrypt(plaintext)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Decrypt(ciphertext); err != nil {
			b.Fatal(err)
		}
	}
}
