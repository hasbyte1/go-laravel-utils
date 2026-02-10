package encryption_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/encryption"
)

// ──────────────────────────────────────────────────────────────────────────────
// Constructor tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNewGCMEncrypter_AcceptsValidKeys(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
		cipher encryption.Cipher
	}{
		{"AES-128-GCM 16-byte key", 16, encryption.AES128GCM},
		{"AES-256-GCM 32-byte key", 32, encryption.AES256GCM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			enc, err := encryption.NewGCMEncrypter(key, tt.cipher)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if enc == nil {
				t.Fatal("expected non-nil encrypter")
			}
		})
	}
}

func TestNewGCMEncrypter_RejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		cipher  encryption.Cipher
		wantErr error
	}{
		{"nil key", nil, encryption.AES256GCM, encryption.ErrEmptyKey},
		{"empty key", []byte{}, encryption.AES256GCM, encryption.ErrEmptyKey},
		{"too short for AES-256", make([]byte, 16), encryption.AES256GCM, encryption.ErrInvalidKeyLength},
		{"too long for AES-128", make([]byte, 32), encryption.AES128GCM, encryption.ErrInvalidKeyLength},
		{"CBC cipher rejected", make([]byte, 32), encryption.AES256CBC, encryption.ErrUnsupportedCipher},
		{"unknown cipher", make([]byte, 32), encryption.Cipher("aes-512-gcm"), encryption.ErrUnsupportedCipher},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryption.NewGCMEncrypter(tt.key, tt.cipher)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tt.wantErr)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Round-trip tests
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMEncryptDecrypt_RoundTrip_AES256GCM(t *testing.T) {
	key, err := encryption.GenerateKey(encryption.AES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("AES-256-GCM authenticated encryption test.")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestGCMEncryptDecrypt_RoundTrip_AES128GCM(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES128GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES128GCM)

	plaintext := []byte("AES-128-GCM test")
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestGCMEncryptString_RoundTrip(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	original := "GCM string round trip — 🔒"
	ct, err := enc.EncryptString(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.DecryptString(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Fatalf("got %q, want %q", got, original)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Edge cases — plaintext sizes
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	ct, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestGCMEncryptDecrypt_BinaryData(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	plaintext := make([]byte, 256)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("binary data round-trip failed")
	}
}

func TestGCMEncrypt_ProducesUniqueOutputs(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	plaintext := []byte("same message")
	ct1, _ := enc.Encrypt(plaintext)
	ct2, _ := enc.Encrypt(plaintext)
	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions must produce different ciphertexts (different nonces)")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Tamper detection
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMDecrypt_TamperedCiphertext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	ct, _ := enc.Encrypt([]byte("authentic data"))
	ct[len(ct)/2] ^= 0x01

	_, err := enc.Decrypt(ct)
	if err == nil {
		t.Error("expected error when decrypting tampered GCM payload")
	}
}

func TestGCMDecrypt_TamperedTag(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	raw, _ := enc.Encrypt([]byte("gcm tamper"))
	jsonBytes, _ := base64.StdEncoding.DecodeString(string(raw))
	var p map[string]string
	_ = json.Unmarshal(jsonBytes, &p)

	// Replace tag with zeros.
	p["tag"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	corrupted, _ := json.Marshal(p)
	tampered := base64.StdEncoding.EncodeToString(corrupted)

	_, err := enc.Decrypt([]byte(tampered))
	if !errors.Is(err, encryption.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestGCMDecrypt_MissingTag(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	raw, _ := enc.Encrypt([]byte("gcm no tag"))
	jsonBytes, _ := base64.StdEncoding.DecodeString(string(raw))
	var p map[string]string
	_ = json.Unmarshal(jsonBytes, &p)
	delete(p, "tag")
	corrupted, _ := json.Marshal(p)
	tampered := base64.StdEncoding.EncodeToString(corrupted)

	_, err := enc.Decrypt([]byte(tampered))
	if !errors.Is(err, encryption.ErrInvalidTag) {
		t.Fatalf("expected ErrInvalidTag, got %v", err)
	}
}

func TestGCMDecrypt_WrongKey(t *testing.T) {
	key1, _ := encryption.GenerateKey(encryption.AES256GCM)
	key2, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc1, _ := encryption.NewGCMEncrypter(key1, encryption.AES256GCM)
	enc2, _ := encryption.NewGCMEncrypter(key2, encryption.AES256GCM)

	ct, _ := enc1.Encrypt([]byte("gcm wrong key"))
	_, err := enc2.Decrypt(ct)
	if !errors.Is(err, encryption.ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Key rotation
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMKeyRotation_PreviousKey(t *testing.T) {
	oldKey, _ := encryption.GenerateKey(encryption.AES256GCM)
	newKey, _ := encryption.GenerateKey(encryption.AES256GCM)

	oldEnc, _ := encryption.NewGCMEncrypter(oldKey, encryption.AES256GCM)
	ct, _ := oldEnc.Encrypt([]byte("gcm rotate"))

	newEnc, _ := encryption.NewGCMEncrypterWithOptions(
		newKey, encryption.AES256GCM,
		encryption.WithPreviousKeys(oldKey),
	)
	got, err := newEnc.Decrypt(ct)
	if err != nil {
		t.Fatalf("GCM key rotation failed: %v", err)
	}
	if string(got) != "gcm rotate" {
		t.Fatalf("got %q", got)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// AppearsEncrypted
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMAppearsEncrypted_ValidPayload(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	ct, _ := enc.Encrypt([]byte("test"))
	if !enc.AppearsEncrypted(ct) {
		t.Error("expected AppearsEncrypted=true for valid GCM payload")
	}
}

func TestGCMAppearsEncrypted_Plaintext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	if enc.AppearsEncrypted([]byte("plain text")) {
		t.Error("expected AppearsEncrypted=false for plaintext")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Cross-cipher isolation
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMPayload_NotDecryptableByCBC(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	gcmEnc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)

	gcmCT, _ := gcmEnc.Encrypt([]byte("gcm data"))

	// A CBC encrypter with the same key should fail (MAC will be missing).
	cbcKey, _ := encryption.GenerateKey(encryption.AES256CBC)
	cbcEnc, _ := encryption.NewEncrypter(cbcKey, encryption.AES256CBC)
	_, err := cbcEnc.Decrypt(gcmCT)
	if err == nil {
		t.Error("CBC encrypter should not decrypt a GCM payload")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Interface compliance
// ──────────────────────────────────────────────────────────────────────────────

func TestGCMEncrypter_SatisfiesEncrypterInterface(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256GCM)
	enc, _ := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
	var _ encryption.Encrypter = enc
	var _ encryption.PayloadInspector = enc
}
