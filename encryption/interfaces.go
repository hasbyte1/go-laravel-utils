package encryption

// Encrypter is the interface satisfied by all encryption backends in this
// package.  It mirrors the surface area of Laravel's Encrypter class so that
// consumers can depend on the interface rather than a concrete type.
//
// Portability note: this interface maps 1-to-1 to class methods in Python or
// Node.js, making cross-language ports straightforward.
//
// To implement a custom backend (e.g. ChaCha20-Poly1305, HSM-backed AES):
//
//  1. Create a struct that holds your key material and any configuration.
//  2. Implement all six methods below.
//  3. Pass the struct wherever an Encrypter is required.
type Encrypter interface {
	// Encrypt encrypts arbitrary bytes and returns the base64-encoded JSON
	// payload produced by this package.
	Encrypt(value []byte) ([]byte, error)

	// EncryptString is a convenience wrapper around Encrypt for string values.
	EncryptString(value string) (string, error)

	// Decrypt decrypts a base64-encoded JSON payload previously produced by
	// Encrypt and returns the original plaintext bytes.
	Decrypt(payload []byte) ([]byte, error)

	// DecryptString is a convenience wrapper around Decrypt for string values.
	DecryptString(payload string) (string, error)

	// GetKey returns a copy of the primary encryption key.
	// Callers must not retain or mutate the returned slice across calls.
	GetKey() []byte

	// GetCipher returns the cipher identifier used by this encrypter.
	GetCipher() Cipher
}

// KeyGenerator is an optional interface that an Encrypter backend may satisfy
// to expose deterministic or hardware-backed key generation.  It is a separate
// interface so that callers focused solely on encrypt/decrypt do not need to
// import generation logic.
type KeyGenerator interface {
	// GenerateKey returns a cryptographically random key suitable for use with
	// the encrypter's configured cipher.
	GenerateKey() ([]byte, error)
}

// PayloadInspector is an optional interface for backends that can cheaply
// detect whether a value appears to be an encrypted payload without performing
// full decryption.
type PayloadInspector interface {
	// AppearsEncrypted returns true if payload has the expected structure of an
	// encrypted value produced by this encrypter.  It does not verify the MAC
	// or attempt decryption.
	AppearsEncrypted(payload []byte) bool
}
