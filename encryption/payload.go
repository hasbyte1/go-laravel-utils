package encryption

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Payload is the JSON structure embedded inside every encrypted value.
//
// The field names and layout are intentionally identical to Laravel's
// Encrypter payload, which makes it possible to decrypt Go-encrypted values
// from PHP and vice-versa, or to port the implementation to Node.js/Python
// using the same on-wire format.
//
// Consumers should treat this type as read-only; use [CBCEncrypter.Decrypt] or
// [GCMEncrypter.Decrypt] to obtain the plaintext.
type Payload struct {
	// IV is the base64-encoded initialisation vector (CBC) or nonce (GCM).
	// AES always uses a 16-byte IV; AES-GCM uses a 12-byte nonce.
	IV string `json:"iv"`

	// Value is the base64-encoded ciphertext.
	Value string `json:"value"`

	// MAC is the hex-encoded HMAC-SHA256 over base64(IV)+base64(Value).
	// It is computed with the encryption key and verified in constant time
	// during decryption.  Empty string for AEAD ciphers (AES-GCM).
	MAC string `json:"mac"`

	// Tag is the base64-encoded AES-GCM authentication tag (16 bytes / 128 bits).
	// Omitted (empty) for non-AEAD ciphers such as AES-CBC.
	Tag string `json:"tag,omitempty"`
}

// marshal serialises p to base64-encoded JSON.
func (p *Payload) marshal() ([]byte, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(out, data)
	return out, nil
}

// unmarshalPayload decodes a base64-encoded JSON payload.
// It accepts standard base64, URL-safe base64, and unpadded variants.
func unmarshalPayload(raw []byte) (*Payload, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, ErrInvalidPayload
	}

	decoded, err := base64Decode(s)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	var p Payload
	if err := json.Unmarshal(decoded, &p); err != nil {
		return nil, ErrInvalidPayload
	}
	return &p, nil
}

// base64Decode attempts multiple base64 variants in order.
func base64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// validate checks that the payload has the required fields for the given mode.
//
//   - isAEAD=false (CBC): IV and Value must be non-empty; MAC must be non-empty.
//     With PKCS#7 padding an encrypted empty plaintext still produces a non-empty
//     ciphertext (one full padding block), so Value is always non-empty for CBC.
//   - isAEAD=true  (GCM): IV and Tag must be non-empty; Value may be empty
//     (which is the correct base64 encoding of an empty ciphertext when the
//     original plaintext was empty); MAC is ignored.
func (p *Payload) validate(isAEAD bool) error {
	if p.IV == "" {
		return ErrInvalidPayload
	}
	if !isAEAD {
		if p.Value == "" || p.MAC == "" {
			return ErrInvalidPayload
		}
	} else {
		if p.Tag == "" {
			return ErrInvalidTag
		}
	}
	return nil
}
