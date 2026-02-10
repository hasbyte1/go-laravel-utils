// Package encryption provides symmetric authenticated encryption inspired by
// Laravel's Encrypter class.  It supports AES-128/256 in CBC mode (with
// HMAC-SHA256 for authentication) and AES-128/256 in GCM mode (AEAD).
//
// # Payload format
//
// Every encrypted value is serialised as a base64-encoded JSON object whose
// shape is identical to the one produced by Laravel's Encrypter:
//
//	{
//	  "iv":    "<base64>",  // initialisation vector / GCM nonce
//	  "value": "<base64>",  // ciphertext
//	  "mac":   "<hex>",     // HMAC-SHA256 (CBC only; empty for GCM)
//	  "tag":   "<base64>"   // AES-GCM authentication tag (GCM only; omitted for CBC)
//	}
//
// This makes it straightforward to share encrypted payloads between Go and
// PHP/Laravel, or to port the implementation to Node.js, Python, etc.
//
// # Quick start
//
//	key, err := encryption.GenerateKey(encryption.AES256CBC)
//	enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
//
//	ciphertext, err := enc.EncryptString("hello")
//	plaintext,  err := enc.DecryptString(ciphertext)
//
// # Security notes
//
//   - A unique random IV is generated for every Encrypt call; never reuse IVs.
//   - Decryption verifies the HMAC/tag before touching the ciphertext, which
//     prevents padding-oracle and chosen-ciphertext attacks.
//   - Use constant-time comparison (crypto/subtle) for all MAC checks.
//   - Keys are cloned on ingestion so that external mutations cannot affect
//     in-use keys.
package encryption

import "fmt"

// Cipher names the encryption algorithm and operating mode.
// The string values are intentionally lowercase to match OpenSSL/Laravel conventions.
type Cipher string

const (
	// AES128CBC uses AES-128 in CBC mode with HMAC-SHA256 authentication.
	AES128CBC Cipher = "aes-128-cbc"
	// AES256CBC uses AES-256 in CBC mode with HMAC-SHA256 authentication.
	AES256CBC Cipher = "aes-256-cbc"
	// AES128GCM uses AES-128 in GCM mode (AEAD — no separate HMAC needed).
	AES128GCM Cipher = "aes-128-gcm"
	// AES256GCM uses AES-256 in GCM mode (AEAD — no separate HMAC needed).
	AES256GCM Cipher = "aes-256-gcm"
)

// cipherSpec holds the per-cipher parameters used for validation.
type cipherSpec struct {
	keySize int  // required key length in bytes
	isAEAD  bool // true for authenticated encryption modes
}

var cipherSpecs = map[Cipher]cipherSpec{
	AES128CBC: {keySize: 16, isAEAD: false},
	AES256CBC: {keySize: 32, isAEAD: false},
	AES128GCM: {keySize: 16, isAEAD: true},
	AES256GCM: {keySize: 32, isAEAD: true},
}

// Supported reports whether key and c form a valid combination.
// It returns false for unknown ciphers or mismatched key lengths.
func Supported(key []byte, c Cipher) bool {
	spec, ok := cipherSpecs[c]
	if !ok {
		return false
	}
	return len(key) == spec.keySize
}

// KeySize returns the required key length in bytes for cipher c.
// It returns -1 for unsupported ciphers.
func KeySize(c Cipher) int {
	if spec, ok := cipherSpecs[c]; ok {
		return spec.keySize
	}
	return -1
}

// IsAEAD reports whether c is an Authenticated Encryption with Associated Data
// algorithm.  AEAD ciphers authenticate in-band and do not need a separate HMAC.
func IsAEAD(c Cipher) bool {
	spec, ok := cipherSpecs[c]
	return ok && spec.isAEAD
}

// ValidateCipher returns a non-nil error if c is not a recognised cipher name.
func ValidateCipher(c Cipher) error {
	if _, ok := cipherSpecs[c]; !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedCipher, c)
	}
	return nil
}
