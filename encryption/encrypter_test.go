package encryption_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/encryption"
)

// ──────────────────────────────────────────────────────────────────────────────
// Constructor tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNewEncrypter_AcceptsValidKeys(t *testing.T) {
	tests := []struct {
		name   string
		keyLen int
		cipher encryption.Cipher
	}{
		{"AES-128-CBC 16-byte key", 16, encryption.AES128CBC},
		{"AES-256-CBC 32-byte key", 32, encryption.AES256CBC},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			enc, err := encryption.NewEncrypter(key, tt.cipher)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if enc == nil {
				t.Fatal("expected non-nil encrypter")
			}
		})
	}
}

func TestNewEncrypter_RejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		cipher  encryption.Cipher
		wantErr error
	}{
		{"nil key", nil, encryption.AES256CBC, encryption.ErrEmptyKey},
		{"empty key", []byte{}, encryption.AES256CBC, encryption.ErrEmptyKey},
		{"too short for AES-256", make([]byte, 16), encryption.AES256CBC, encryption.ErrInvalidKeyLength},
		{"too long for AES-128", make([]byte, 32), encryption.AES128CBC, encryption.ErrInvalidKeyLength},
		{"unknown cipher", make([]byte, 32), encryption.Cipher("aes-512-cbc"), encryption.ErrUnsupportedCipher},
		{"AEAD cipher rejected", make([]byte, 32), encryption.AES256GCM, encryption.ErrUnsupportedCipher},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryption.NewEncrypter(tt.key, tt.cipher)
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

func TestEncryptDecrypt_RoundTrip_AES256CBC(t *testing.T) {
	key, err := encryption.GenerateKey(encryption.AES256CBC)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello, World! This is a round-trip test.")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}

	got, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptDecrypt_RoundTrip_AES128CBC(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES128CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES128CBC)

	plaintext := []byte("AES-128-CBC round trip")
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

func TestEncryptString_RoundTrip(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	original := "secret message — unicode: 日本語 🔐"
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

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	ct, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty slice: %v", err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt empty slice: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestEncryptDecrypt_SingleByte(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	for _, b := range []byte{0x00, 0x01, 0x7f, 0x80, 0xff} {
		ct, err := enc.Encrypt([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		got, err := enc.Decrypt(ct)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != b {
			t.Fatalf("byte 0x%02x: got %v", b, got)
		}
	}
}

func TestEncryptDecrypt_ExactBlockBoundary(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	// 16-byte plaintext (exactly one AES block) requires a full extra padding block.
	plaintext := bytes.Repeat([]byte("A"), 16)
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("block-boundary round-trip failed")
	}
}

func TestEncryptDecrypt_BinaryData(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	// All 256 byte values.
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

func TestEncryptDecrypt_LargePlaintext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	plaintext := bytes.Repeat([]byte("Go encryption "), 1<<16) // ~896 KiB
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("large plaintext round-trip failed")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Uniqueness / IV randomness
// ──────────────────────────────────────────────────────────────────────────────

func TestEncrypt_ProducesUniqueOutputs(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	plaintext := []byte("same message encrypted twice")
	ct1, _ := enc.Encrypt(plaintext)
	ct2, _ := enc.Encrypt(plaintext)
	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same plaintext must produce different ciphertexts (different IVs)")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Tamper detection
// ──────────────────────────────────────────────────────────────────────────────

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	ct, _ := enc.Encrypt([]byte("tamper me"))
	// Flip one bit in the middle of the base64 payload.
	ct[len(ct)/2] ^= 0x01

	_, err := enc.Decrypt(ct)
	if err == nil {
		t.Error("expected error when decrypting tampered payload")
	}
}

func TestDecrypt_TamperedMAC(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	raw, _ := enc.Encrypt([]byte("data"))
	// Decode the payload JSON, corrupt the MAC, re-encode.
	jsonBytes, _ := base64.StdEncoding.DecodeString(string(raw))
	var p map[string]string
	_ = json.Unmarshal(jsonBytes, &p)
	p["mac"] = strings.Repeat("0", 64) // replace with zeros
	corrupted, _ := json.Marshal(p)
	tampered := base64.StdEncoding.EncodeToString(corrupted)

	_, err := enc.Decrypt([]byte(tampered))
	if !errors.Is(err, encryption.ErrInvalidMAC) {
		t.Fatalf("expected ErrInvalidMAC, got %v", err)
	}
}

func TestDecrypt_TamperedIV(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	raw, _ := enc.Encrypt([]byte("iv tamper"))
	jsonBytes, _ := base64.StdEncoding.DecodeString(string(raw))
	var p map[string]string
	_ = json.Unmarshal(jsonBytes, &p)
	// Replace the IV with a different valid-looking base64 value.
	iv := make([]byte, 16)
	iv[0] = 0xff
	p["iv"] = base64.StdEncoding.EncodeToString(iv)
	corrupted, _ := json.Marshal(p)
	tampered := base64.StdEncoding.EncodeToString(corrupted)

	_, err := enc.Decrypt([]byte(tampered))
	if err == nil {
		t.Error("expected error when IV is tampered")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Invalid input handling
// ──────────────────────────────────────────────────────────────────────────────

func TestDecrypt_InvalidBase64(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	_, err := enc.Decrypt([]byte("not-valid-base64!!!"))
	if !errors.Is(err, encryption.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}

func TestDecrypt_EmptyPayload(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	_, err := enc.Decrypt([]byte(""))
	if !errors.Is(err, encryption.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}

func TestDecrypt_ValidBase64ButNotJSON(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	payload := base64.StdEncoding.EncodeToString([]byte("not json at all"))
	_, err := enc.Decrypt([]byte(payload))
	if !errors.Is(err, encryption.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}

func TestDecrypt_MissingFields(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	cases := []map[string]string{
		{"value": "abc", "mac": "def"},               // missing iv
		{"iv": "abc", "mac": "def"},                  // missing value
		{"iv": "abc", "value": "def"},                // missing mac
		{"iv": "", "value": "def", "mac": "abc"},     // empty iv
	}
	for _, c := range cases {
		j, _ := json.Marshal(c)
		payload := base64.StdEncoding.EncodeToString(j)
		_, err := enc.Decrypt([]byte(payload))
		if !errors.Is(err, encryption.ErrInvalidPayload) {
			t.Errorf("case %v: expected ErrInvalidPayload, got %v", c, err)
		}
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := encryption.GenerateKey(encryption.AES256CBC)
	key2, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc1, _ := encryption.NewEncrypter(key1, encryption.AES256CBC)
	enc2, _ := encryption.NewEncrypter(key2, encryption.AES256CBC)

	ct, _ := enc1.Encrypt([]byte("secret"))
	_, err := enc2.Decrypt(ct)
	if !errors.Is(err, encryption.ErrInvalidMAC) {
		t.Fatalf("expected ErrInvalidMAC, got %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Key rotation
// ──────────────────────────────────────────────────────────────────────────────

func TestKeyRotation_DecryptWithPreviousKey(t *testing.T) {
	oldKey, _ := encryption.GenerateKey(encryption.AES256CBC)
	newKey, _ := encryption.GenerateKey(encryption.AES256CBC)

	oldEnc, _ := encryption.NewEncrypter(oldKey, encryption.AES256CBC)
	ct, _ := oldEnc.Encrypt([]byte("rotate me"))

	// New encrypter should decrypt values encrypted by the old key.
	newEnc, _ := encryption.NewEncrypterWithOptions(
		newKey, encryption.AES256CBC,
		encryption.WithPreviousKeys(oldKey),
	)
	got, err := newEnc.Decrypt(ct)
	if err != nil {
		t.Fatalf("key rotation decryption failed: %v", err)
	}
	if string(got) != "rotate me" {
		t.Fatalf("got %q, want %q", got, "rotate me")
	}
}

func TestKeyRotation_NewKeyTakesPrecedence(t *testing.T) {
	oldKey, _ := encryption.GenerateKey(encryption.AES256CBC)
	newKey, _ := encryption.GenerateKey(encryption.AES256CBC)

	enc, _ := encryption.NewEncrypterWithOptions(
		newKey, encryption.AES256CBC,
		encryption.WithPreviousKeys(oldKey),
	)
	// Encrypting should use the primary (new) key.
	ct, _ := enc.Encrypt([]byte("new key encrypted"))

	// Decrypting with only the new key should succeed.
	newOnly, _ := encryption.NewEncrypter(newKey, encryption.AES256CBC)
	got, err := newOnly.Decrypt(ct)
	if err != nil {
		t.Fatalf("expected primary key to be used for encryption: %v", err)
	}
	if string(got) != "new key encrypted" {
		t.Fatalf("got %q", got)
	}
}

func TestKeyRotation_MultiplePreviousKeys(t *testing.T) {
	key1, _ := encryption.GenerateKey(encryption.AES256CBC)
	key2, _ := encryption.GenerateKey(encryption.AES256CBC)
	key3, _ := encryption.GenerateKey(encryption.AES256CBC) // current

	enc1, _ := encryption.NewEncrypter(key1, encryption.AES256CBC)
	enc2, _ := encryption.NewEncrypter(key2, encryption.AES256CBC)

	ct1, _ := enc1.Encrypt([]byte("key1 value"))
	ct2, _ := enc2.Encrypt([]byte("key2 value"))

	current, _ := encryption.NewEncrypterWithOptions(
		key3, encryption.AES256CBC,
		encryption.WithPreviousKeys(key1, key2),
	)

	got1, err := current.Decrypt(ct1)
	if err != nil || string(got1) != "key1 value" {
		t.Fatalf("failed to decrypt key1 value: %v", err)
	}
	got2, err := current.Decrypt(ct2)
	if err != nil || string(got2) != "key2 value" {
		t.Fatalf("failed to decrypt key2 value: %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Key management helpers
// ──────────────────────────────────────────────────────────────────────────────

func TestGetKey_ReturnsCopy(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	got := enc.GetKey()
	got[0] ^= 0xff // mutate the copy

	ct, _ := enc.Encrypt([]byte("mutation test"))
	_, err := enc.Decrypt(ct)
	if err != nil {
		t.Error("internal key should be unaffected by mutating GetKey() result")
	}
}

func TestGenerateKey_CorrectLength(t *testing.T) {
	tests := []struct {
		cipher  encryption.Cipher
		wantLen int
	}{
		{encryption.AES128CBC, 16},
		{encryption.AES256CBC, 32},
		{encryption.AES128GCM, 16},
		{encryption.AES256GCM, 32},
	}
	for _, tt := range tests {
		key, err := encryption.GenerateKey(tt.cipher)
		if err != nil {
			t.Fatalf("%s: %v", tt.cipher, err)
		}
		if len(key) != tt.wantLen {
			t.Fatalf("%s: got %d bytes, want %d", tt.cipher, len(key), tt.wantLen)
		}
	}
}

func TestGenerateKey_UnknownCipher(t *testing.T) {
	_, err := encryption.GenerateKey(encryption.Cipher("aes-999-cbc"))
	if !errors.Is(err, encryption.ErrUnsupportedCipher) {
		t.Fatalf("expected ErrUnsupportedCipher, got %v", err)
	}
}

func TestEncodeDecodeKey_RoundTrip(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	encoded := encryption.EncodeKey(key)
	if encoded == "" {
		t.Fatal("EncodeKey returned empty string")
	}
	decoded, err := encryption.DecodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatal("decoded key does not match original")
	}
}

func TestDecodeKey_InvalidBase64(t *testing.T) {
	_, err := encryption.DecodeKey("not!!!valid===base64")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// AppearsEncrypted
// ──────────────────────────────────────────────────────────────────────────────

func TestAppearsEncrypted_ValidPayload(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	ct, _ := enc.Encrypt([]byte("test"))
	if !enc.AppearsEncrypted(ct) {
		t.Error("expected AppearsEncrypted=true for valid payload")
	}
}

func TestAppearsEncrypted_Plaintext(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	if enc.AppearsEncrypted([]byte("plain text")) {
		t.Error("expected AppearsEncrypted=false for plaintext")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Interface compliance
// ──────────────────────────────────────────────────────────────────────────────

func TestCBCEncrypter_SatisfiesEncrypterInterface(t *testing.T) {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)
	var _ encryption.Encrypter = enc
	var _ encryption.PayloadInspector = enc
}

// ──────────────────────────────────────────────────────────────────────────────
// Cipher helpers
// ──────────────────────────────────────────────────────────────────────────────

func TestSupported(t *testing.T) {
	key16 := make([]byte, 16)
	key32 := make([]byte, 32)

	if !encryption.Supported(key16, encryption.AES128CBC) {
		t.Error("16-byte key should be supported for AES-128-CBC")
	}
	if !encryption.Supported(key32, encryption.AES256CBC) {
		t.Error("32-byte key should be supported for AES-256-CBC")
	}
	if encryption.Supported(key16, encryption.AES256CBC) {
		t.Error("16-byte key should not be supported for AES-256-CBC")
	}
	if encryption.Supported(key32, encryption.Cipher("bogus")) {
		t.Error("unknown cipher should not be supported")
	}
}

func TestIsAEAD(t *testing.T) {
	if encryption.IsAEAD(encryption.AES128CBC) {
		t.Error("AES-128-CBC is not AEAD")
	}
	if encryption.IsAEAD(encryption.AES256CBC) {
		t.Error("AES-256-CBC is not AEAD")
	}
	if !encryption.IsAEAD(encryption.AES128GCM) {
		t.Error("AES-128-GCM should be AEAD")
	}
	if !encryption.IsAEAD(encryption.AES256GCM) {
		t.Error("AES-256-GCM should be AEAD")
	}
}

func TestKeySize(t *testing.T) {
	tests := []struct {
		cipher  encryption.Cipher
		wantLen int
	}{
		{encryption.AES128CBC, 16},
		{encryption.AES256CBC, 32},
		{encryption.AES128GCM, 16},
		{encryption.AES256GCM, 32},
		{encryption.Cipher("unknown"), -1},
	}
	for _, tt := range tests {
		if got := encryption.KeySize(tt.cipher); got != tt.wantLen {
			t.Errorf("KeySize(%q) = %d, want %d", tt.cipher, got, tt.wantLen)
		}
	}
}
