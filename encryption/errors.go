package encryption

import "errors"

// Sentinel errors returned by encryption operations.
//
// Callers should use errors.Is for comparisons:
//
//	_, err := enc.Decrypt(payload)
//	if errors.Is(err, encryption.ErrInvalidMAC) {
//	    // payload was tampered with
//	}
var (
	// ErrInvalidPayload is returned when the encrypted payload is malformed,
	// cannot be base64-decoded, is not valid JSON, or is missing required fields.
	ErrInvalidPayload = errors.New("encryption: invalid payload")

	// ErrInvalidMAC is returned when HMAC-SHA256 verification fails.
	// This indicates the ciphertext or IV may have been tampered with.
	// Security note: always treat this as a hard failure; do not fall back to
	// decrypting without authentication.
	ErrInvalidMAC = errors.New("encryption: invalid MAC — payload may have been tampered with")

	// ErrInvalidTag is returned when the AES-GCM authentication tag is absent,
	// cannot be decoded, or has an unexpected length.
	ErrInvalidTag = errors.New("encryption: invalid or missing authentication tag")

	// ErrInvalidKeyLength is returned when the provided key does not satisfy
	// the key-size requirement of the selected cipher.
	ErrInvalidKeyLength = errors.New("encryption: invalid key length for cipher")

	// ErrUnsupportedCipher is returned when an unrecognised cipher name is used.
	ErrUnsupportedCipher = errors.New("encryption: unsupported cipher")

	// ErrDecryptionFailed is returned when the underlying decryption operation
	// cannot complete — for example, because the ciphertext length is not a
	// multiple of the block size, or PKCS#7 padding is malformed.
	ErrDecryptionFailed = errors.New("encryption: decryption failed")

	// ErrEmptyKey is returned when a nil or zero-length key is provided.
	ErrEmptyKey = errors.New("encryption: key must not be empty")
)
