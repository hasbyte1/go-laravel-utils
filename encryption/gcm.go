package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

const (
	// gcmTagSize is the AES-GCM authentication tag length in bytes (128 bits).
	// This matches PHP's openssl_encrypt tag length parameter default.
	gcmTagSize = 16
)

// GCMEncrypter provides AES-128-GCM or AES-256-GCM authenticated encryption.
//
// AES-GCM is an AEAD (Authenticated Encryption with Associated Data) cipher:
// it provides both confidentiality and integrity in a single operation, so no
// separate HMAC is needed.  The authentication tag is embedded in the payload's
// "tag" field, while the "mac" field is left empty — exactly as Laravel does.
//
// # Nonce management
//
// A fresh 12-byte nonce is generated for every [GCMEncrypter.Encrypt] call
// using crypto/rand.  With 96-bit nonces and random generation, the collision
// probability becomes non-negligible after approximately 2^32 messages under
// the same key.  For high-volume applications, rotate keys before reaching
// that threshold.
//
// # Key rotation
//
// Use [WithPreviousKeys] to register old keys that should still be accepted
// during decryption.
type GCMEncrypter struct {
	key  []byte
	c    Cipher
	opts encrypterOptions
}

// NewGCMEncrypter constructs a [GCMEncrypter] for the given key and cipher.
//
// Valid ciphers: [AES128GCM], [AES256GCM].
// Key length must match the cipher's requirement (16 or 32 bytes).
func NewGCMEncrypter(key []byte, c Cipher) (*GCMEncrypter, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	if err := ValidateCipher(c); err != nil {
		return nil, err
	}
	if !IsAEAD(c) {
		return nil, fmt.Errorf("%w: %q is not an AEAD cipher — use NewEncrypter instead", ErrUnsupportedCipher, c)
	}
	if !Supported(key, c) {
		return nil, fmt.Errorf("%w: %q requires a %d-byte key, got %d bytes",
			ErrInvalidKeyLength, c, KeySize(c), len(key))
	}
	return &GCMEncrypter{key: cloneBytes(key), c: c}, nil
}

// NewGCMEncrypterWithOptions constructs a [GCMEncrypter] and applies
// functional options such as [WithPreviousKeys].
func NewGCMEncrypterWithOptions(key []byte, c Cipher, opts ...Option) (*GCMEncrypter, error) {
	enc, err := NewGCMEncrypter(key, c)
	if err != nil {
		return nil, err
	}
	for _, o := range opts {
		o(&enc.opts)
	}
	return enc, nil
}

// GetKey returns a copy of the primary encryption key.
func (e *GCMEncrypter) GetKey() []byte { return cloneBytes(e.key) }

// GetCipher returns the cipher identifier.
func (e *GCMEncrypter) GetCipher() Cipher { return e.c }

// Encrypt encrypts value with AES-GCM.
//
// The returned bytes are the base64-encoded JSON payload.  The authentication
// tag is stored in the payload's "tag" field; "mac" is always empty.  The
// format is identical to Laravel's AEAD payload.
func (e *GCMEncrypter) Encrypt(value []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to initialise AES-GCM: %w", err)
	}

	// Generate a fresh 12-byte nonce.
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// gcm.Seal appends the tag after the ciphertext: output = ciphertext || tag.
	sealed := gcm.Seal(nil, nonce, value, nil)
	ciphertext := sealed[:len(sealed)-gcmTagSize]
	tag := sealed[len(sealed)-gcmTagSize:]

	p := &Payload{
		IV:    base64.StdEncoding.EncodeToString(nonce),
		Value: base64.StdEncoding.EncodeToString(ciphertext),
		MAC:   "",
		Tag:   base64.StdEncoding.EncodeToString(tag),
	}
	return p.marshal()
}

// EncryptString is a convenience wrapper that encrypts a UTF-8 string.
func (e *GCMEncrypter) EncryptString(value string) (string, error) {
	out, err := e.Encrypt([]byte(value))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Decrypt decrypts a base64-encoded JSON payload produced by [GCMEncrypter.Encrypt].
//
// AES-GCM verifies the authentication tag as part of decryption; if the tag
// is invalid (tampered ciphertext, wrong key, etc.) [ErrDecryptionFailed] is
// returned.
//
// If [WithPreviousKeys] was configured, each key is tried until decryption
// succeeds or all keys are exhausted.
func (e *GCMEncrypter) Decrypt(payload []byte) ([]byte, error) {
	return e.decryptWithKeys(payload, e.allKeys())
}

// DecryptString is a convenience wrapper around [GCMEncrypter.Decrypt].
func (e *GCMEncrypter) DecryptString(payload string) (string, error) {
	out, err := e.Decrypt([]byte(payload))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// AppearsEncrypted returns true if payload has the structural shape of a GCM
// payload produced by this encrypter.  It does not attempt decryption.
//
// Implements [PayloadInspector].
func (e *GCMEncrypter) AppearsEncrypted(payload []byte) bool {
	p, err := unmarshalPayload(payload)
	if err != nil {
		return false
	}
	return p.validate(true) == nil
}

func (e *GCMEncrypter) decryptWithKeys(payload []byte, keys [][]byte) ([]byte, error) {
	p, err := unmarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	if err := p.validate(true); err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(p.IV)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	ciphertext, err := base64.StdEncoding.DecodeString(p.Value)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	tag, err := base64.StdEncoding.DecodeString(p.Tag)
	if err != nil {
		return nil, ErrInvalidTag
	}
	if len(tag) != gcmTagSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidTag, gcmTagSize, len(tag))
	}

	// Try each key; the first that successfully opens the sealed box wins.
	for _, key := range keys {
		plaintext, err := decryptGCM(ciphertext, tag, nonce, key)
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrDecryptionFailed
}

// decryptGCM performs raw AES-GCM decryption and tag verification.
func decryptGCM(ciphertext, tag, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to initialise AES-GCM: %w", err)
	}

	// gcm.Open expects sealed = ciphertext || tag.
	sealed := append(ciphertext, tag...) //nolint:gocritic // intentional copy via append
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func (e *GCMEncrypter) allKeys() [][]byte {
	keys := make([][]byte, 0, 1+len(e.opts.previousKeys))
	keys = append(keys, e.key)
	keys = append(keys, e.opts.previousKeys...)
	return keys
}
