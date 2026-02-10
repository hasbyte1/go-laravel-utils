package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateKey returns a cryptographically random key suitable for the given
// cipher.  The key is generated with crypto/rand and is ready to pass directly
// to [NewEncrypter] or [NewGCMEncrypter].
//
// Example:
//
//	key, err := encryption.GenerateKey(encryption.AES256CBC)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
func GenerateKey(c Cipher) ([]byte, error) {
	size := KeySize(c)
	if size < 0 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCipher, c)
	}
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("encryption: failed to generate random key: %w", err)
	}
	return key, nil
}

// EncodeKey returns the standard base64 encoding of key, suitable for
// storing in a configuration file or environment variable.
//
// Example:
//
//	encoded := encryption.EncodeKey(key)
//	// Store encoded in APP_KEY or similar
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// DecodeKey decodes a base64-encoded key previously produced by [EncodeKey].
// It accepts both standard and URL-safe base64 alphabets.
//
// Example:
//
//	key, err := encryption.DecodeKey(os.Getenv("APP_KEY"))
func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil {
		return key, nil
	}
	// Try URL-safe variant before giving up.
	key, err = base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to decode key: %w", err)
	}
	return key, nil
}

// randomBytes returns n cryptographically random bytes from crypto/rand.
// It is used internally for IV and nonce generation.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("encryption: failed to generate %d random bytes: %w", n, err)
	}
	return b, nil
}
