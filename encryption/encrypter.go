package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Option is a functional option for configuring a [CBCEncrypter] or
// [GCMEncrypter].  Options are applied at construction time via
// [NewEncrypterWithOptions] / [NewGCMEncrypterWithOptions].
type Option func(*encrypterOptions)

// encrypterOptions holds the optional runtime configuration shared by all
// encrypter types.
type encrypterOptions struct {
	// previousKeys are tried in order during decryption when the primary key
	// fails MAC/tag verification.  They are never used for encryption.
	previousKeys [][]byte
}

// WithPreviousKeys registers fallback keys to try during decryption.
// This supports key-rotation workflows: encrypt all new values with the
// current primary key, while still being able to decrypt values that were
// encrypted with older keys.
//
// Example:
//
//	enc, _ := encryption.NewEncrypterWithOptions(
//	    newKey, encryption.AES256CBC,
//	    encryption.WithPreviousKeys(oldKey1, oldKey2),
//	)
func WithPreviousKeys(keys ...[]byte) Option {
	return func(o *encrypterOptions) {
		for _, k := range keys {
			o.previousKeys = append(o.previousKeys, cloneBytes(k))
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// CBCEncrypter
// ──────────────────────────────────────────────────────────────────────────────

// CBCEncrypter provides AES-128-CBC or AES-256-CBC encryption authenticated
// with HMAC-SHA256.  It is the Go equivalent of Laravel's Encrypter when
// configured with a CBC cipher.
//
// The on-wire payload format is identical to Laravel's, enabling encrypted
// values to be shared between Go and PHP services without modification.
//
// # Threat model
//
//   - Decryption verifies the HMAC before touching the ciphertext, preventing
//     padding-oracle and chosen-ciphertext attacks.
//   - HMAC comparison uses [crypto/subtle.ConstantTimeCompare] to prevent
//     timing-based MAC forgery.
//   - A fresh random IV is generated for every [CBCEncrypter.Encrypt] call.
//
// # Key rotation
//
// Use [WithPreviousKeys] to register old keys that should still be accepted
// during decryption.  The primary key is always tried first; previous keys
// are tried in the order they were registered.
type CBCEncrypter struct {
	key    []byte
	c      Cipher
	opts   encrypterOptions
}

// NewEncrypter constructs a [CBCEncrypter] for the given key and cipher.
//
// Valid ciphers: [AES128CBC], [AES256CBC].
// Key length must match the cipher's requirement (16 or 32 bytes).
//
// Use [GenerateKey] to obtain a suitable random key.
func NewEncrypter(key []byte, c Cipher) (*CBCEncrypter, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	if IsAEAD(c) {
		return nil, fmt.Errorf("%w: %q is an AEAD cipher — use NewGCMEncrypter instead", ErrUnsupportedCipher, c)
	}
	if err := ValidateCipher(c); err != nil {
		return nil, err
	}
	if !Supported(key, c) {
		return nil, fmt.Errorf("%w: %q requires a %d-byte key, got %d bytes",
			ErrInvalidKeyLength, c, KeySize(c), len(key))
	}
	return &CBCEncrypter{key: cloneBytes(key), c: c}, nil
}

// NewEncrypterWithOptions constructs a [CBCEncrypter] and applies functional
// options such as [WithPreviousKeys].
func NewEncrypterWithOptions(key []byte, c Cipher, opts ...Option) (*CBCEncrypter, error) {
	enc, err := NewEncrypter(key, c)
	if err != nil {
		return nil, err
	}
	for _, o := range opts {
		o(&enc.opts)
	}
	return enc, nil
}

// GetKey returns a copy of the primary encryption key.
// Mutating the returned slice does not affect the encrypter.
func (e *CBCEncrypter) GetKey() []byte { return cloneBytes(e.key) }

// GetCipher returns the cipher identifier.
func (e *CBCEncrypter) GetCipher() Cipher { return e.c }

// Encrypt encrypts value with AES-CBC and authenticates it with HMAC-SHA256.
//
// The returned bytes are the base64-encoded JSON payload.  Each call
// generates a fresh random IV, so encrypting the same plaintext twice
// produces different outputs.
//
// The payload is compatible with Laravel's Encrypter output for CBC ciphers.
func (e *CBCEncrypter) Encrypt(value []byte) ([]byte, error) {
	// Step 1: generate a random 16-byte IV (AES block size is always 16).
	iv, err := randomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// Step 2: PKCS#7-pad the plaintext to an AES block boundary.
	padded := pkcs7Pad(value, aes.BlockSize)

	// Step 3: encrypt with AES-CBC.
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to create AES cipher: %w", err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// Step 4: base64-encode IV and ciphertext separately.
	// PHP's openssl_encrypt (flag 0) produces base64 output, so $value in the
	// payload is already base64.  We replicate that here.
	b64IV := base64.StdEncoding.EncodeToString(iv)
	b64Value := base64.StdEncoding.EncodeToString(ciphertext)

	// Step 5: HMAC-SHA256 over base64(IV) || base64(ciphertext).
	// This matches Laravel's hash($iv, $value, $key) = hash_hmac('sha256', $iv.$value, $key).
	mac := computeMAC([]byte(b64IV+b64Value), e.key)

	// Step 6: build and marshal the payload.
	p := &Payload{IV: b64IV, Value: b64Value, MAC: mac}
	return p.marshal()
}

// EncryptString is a convenience wrapper that encrypts a UTF-8 string and
// returns the base64-encoded JSON payload as a string.
func (e *CBCEncrypter) EncryptString(value string) (string, error) {
	out, err := e.Encrypt([]byte(value))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Decrypt decrypts a base64-encoded JSON payload produced by [CBCEncrypter.Encrypt].
//
// The HMAC is verified in constant time before decryption begins.  If
// [WithPreviousKeys] was configured, each key is tried in order (primary first)
// until a valid MAC is found or all keys are exhausted.
//
// Possible errors: [ErrInvalidPayload], [ErrInvalidMAC], [ErrDecryptionFailed].
func (e *CBCEncrypter) Decrypt(payload []byte) ([]byte, error) {
	return e.decryptWithKeys(payload, e.allKeys())
}

// DecryptString is a convenience wrapper around [CBCEncrypter.Decrypt] for
// string payloads.
func (e *CBCEncrypter) DecryptString(payload string) (string, error) {
	out, err := e.Decrypt([]byte(payload))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// AppearsEncrypted returns true if payload has the structural shape of a
// payload produced by this encrypter.  It does not verify the MAC or attempt
// decryption.
//
// Implements [PayloadInspector].
func (e *CBCEncrypter) AppearsEncrypted(payload []byte) bool {
	p, err := unmarshalPayload(payload)
	if err != nil {
		return false
	}
	return p.validate(false) == nil
}

// decryptWithKeys attempts decryption with each key in turn, returning the
// result from the first key whose MAC matches.
func (e *CBCEncrypter) decryptWithKeys(payload []byte, keys [][]byte) ([]byte, error) {
	p, err := unmarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	if err := p.validate(false); err != nil {
		return nil, err
	}

	// Decode IV.
	iv, err := base64.StdEncoding.DecodeString(p.IV)
	if err != nil {
		return nil, ErrInvalidPayload
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrInvalidPayload
	}

	// Decode ciphertext.
	ciphertext, err := base64.StdEncoding.DecodeString(p.Value)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	// Try each key.  The HMAC is verified before any decryption is attempted.
	for _, key := range keys {
		expected := computeMAC([]byte(p.IV+p.Value), key)
		// ConstantTimeCompare guards against timing-based MAC forgery.
		// Both expected and p.MAC are hex-encoded SHA256 outputs (64 chars), so
		// they will always have the same length.
		if subtle.ConstantTimeCompare([]byte(expected), []byte(p.MAC)) == 1 {
			return decryptCBC(ciphertext, iv, key)
		}
	}
	return nil, ErrInvalidMAC
}

// decryptCBC performs the raw AES-CBC decryption and strips PKCS#7 padding.
func decryptCBC(ciphertext, iv, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecryptionFailed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encryption: failed to create AES cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// allKeys returns the primary key followed by any previous keys.
func (e *CBCEncrypter) allKeys() [][]byte {
	keys := make([][]byte, 0, 1+len(e.opts.previousKeys))
	keys = append(keys, e.key)
	keys = append(keys, e.opts.previousKeys...)
	return keys
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

// computeMAC returns the hex-encoded HMAC-SHA256 of data under key.
// This matches PHP's hash_hmac('sha256', $data, $key) which also returns hex.
func computeMAC(data, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// cloneBytes returns a fresh copy of b.  Used to ensure callers cannot
// mutate keys stored inside an encrypter.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
