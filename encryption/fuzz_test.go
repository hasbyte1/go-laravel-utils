package encryption_test

import (
	"bytes"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/encryption"
)

// FuzzCBCDecrypt ensures that CBCEncrypter.Decrypt never panics on arbitrary
// input and always returns either a valid plaintext or a well-typed error.
//
// Run with: go test -fuzz=FuzzCBCDecrypt ./encryption/
func FuzzCBCDecrypt(f *testing.F) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	// Seed corpus: valid encrypted payloads and known-invalid inputs.
	seeds := [][]byte{
		[]byte(""),
		[]byte("not base64"),
		[]byte("e30="), // base64("{}")
	}
	for _, pt := range []string{"hello", "a", "longer plaintext value"} {
		ct, _ := enc.Encrypt([]byte(pt))
		seeds = append(seeds, ct)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		// Must not panic; error is acceptable.
		_, _ = enc.Decrypt(payload)
	})
}

// FuzzCBCEncrypt ensures that CBCEncrypter.Encrypt never panics on arbitrary
// plaintext and always produces output that can be re-decrypted correctly.
func FuzzCBCEncrypt(f *testing.F) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff})
	f.Add(bytes.Repeat([]byte{0xAA}, 1024))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt returned unexpected error: %v", err)
		}
		got, err := enc.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt failed after Encrypt succeeded: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch for input len=%d", len(plaintext))
		}
	})
}

// FuzzGCMDecrypt ensures that GCMEncrypter.Decrypt never panics on arbitrary
// input.
func FuzzGCMDecrypt(f *testing.F) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	seeds := [][]byte{
		[]byte(""),
		[]byte("not base64!!!"),
		[]byte("e30="),
	}
	for _, pt := range []string{"gcm hello", "x"} {
		ct, _ := enc.Encrypt([]byte(pt))
		seeds = append(seeds, ct)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = enc.Decrypt(payload)
	})
}

// FuzzGCMEncrypt ensures that GCMEncrypter.Encrypt always produces valid
// round-trippable output.
func FuzzGCMEncrypt(f *testing.F) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	f.Add([]byte(""))
	f.Add([]byte("gcm fuzz"))
	f.Add([]byte{0x00, 0xff})

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt returned unexpected error: %v", err)
		}
		got, err := enc.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt failed after Encrypt succeeded: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch for input len=%d", len(plaintext))
		}
	})
}
