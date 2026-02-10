package encryption_test

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hasbyte1/go-laravel-utils/encryption"
)

// ──────────────────────────────────────────────────────────────────────────────
// CBC examples
// ──────────────────────────────────────────────────────────────────────────────

// Example_basicUsage demonstrates the simplest encrypt / decrypt workflow.
func Example_basicUsage() {
	// Generate a random 32-byte key for AES-256-CBC.
	key, err := encryption.GenerateKey(encryption.AES256CBC)
	if err != nil {
		log.Fatal(err)
	}

	// Construct an encrypter.
	enc, err := encryption.NewEncrypter(key, encryption.AES256CBC)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt a string.
	ciphertext, err := enc.EncryptString("Hello, World!")
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt it back.
	plaintext, err := enc.DecryptString(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(plaintext)
	// Output: Hello, World!
}

// Example_keyEncoding shows how to persist and restore a key via base64.
func Example_keyEncoding() {
	// Generate once (e.g., at deploy time).
	key, _ := encryption.GenerateKey(encryption.AES256CBC)

	// Store this in APP_KEY or a secrets manager.
	encoded := encryption.EncodeKey(key)

	// Later, restore the key from the encoded string.
	restored, err := encryption.DecodeKey(encoded)
	if err != nil {
		log.Fatal(err)
	}

	enc, _ := encryption.NewEncrypter(restored, encryption.AES256CBC)
	ct, _ := enc.EncryptString("persisted key test")
	got, _ := enc.DecryptString(ct)

	fmt.Println(got)
	// Output: persisted key test
}

// Example_keyRotation shows how to decrypt values encrypted by an old key
// while using a new key for all new encryptions.
func Example_keyRotation() {
	oldKey, _ := encryption.GenerateKey(encryption.AES256CBC)
	newKey, _ := encryption.GenerateKey(encryption.AES256CBC)

	// Something encrypted by the old system.
	oldEnc, _ := encryption.NewEncrypter(oldKey, encryption.AES256CBC)
	legacy, _ := oldEnc.EncryptString("legacy secret")

	// New encrypter accepts old key as a fallback.
	enc, _ := encryption.NewEncrypterWithOptions(
		newKey, encryption.AES256CBC,
		encryption.WithPreviousKeys(oldKey),
	)

	// New values are encrypted with the new key.
	_, _ = enc.EncryptString("new secret")

	// Old values can still be decrypted.
	plaintext, err := enc.DecryptString(legacy)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(plaintext)
	// Output: legacy secret
}

// Example_encryptBytes demonstrates encrypting arbitrary binary data.
func Example_encryptBytes() {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	// Encrypt a JSON-encoded struct.
	type Config struct {
		DBPassword string `json:"db_password"`
		APIKey     string `json:"api_key"`
	}
	cfg := Config{DBPassword: "hunter2", APIKey: "sk-abc123"}
	raw, _ := json.Marshal(cfg)

	ciphertext, _ := enc.Encrypt(raw)
	plaintext, _ := enc.Decrypt(ciphertext)

	var restored Config
	_ = json.Unmarshal(plaintext, &restored)

	fmt.Println(restored.DBPassword)
	// Output: hunter2
}

// Example_appearsEncrypted shows how to check whether a value is already
// encrypted before attempting to encrypt it again.
func Example_appearsEncrypted() {
	key, _ := encryption.GenerateKey(encryption.AES256CBC)
	enc, _ := encryption.NewEncrypter(key, encryption.AES256CBC)

	ct, _ := enc.EncryptString("some value")

	fmt.Println(enc.AppearsEncrypted([]byte(ct)))
	fmt.Println(enc.AppearsEncrypted([]byte("plain text")))
	// Output:
	// true
	// false
}

// ──────────────────────────────────────────────────────────────────────────────
// GCM examples
// ──────────────────────────────────────────────────────────────────────────────

// Example_gcmUsage demonstrates AES-256-GCM (AEAD) encryption.
func Example_gcmUsage() {
	key, err := encryption.GenerateKey(encryption.AES256GCM)
	if err != nil {
		log.Fatal(err)
	}

	enc, err := encryption.NewGCMEncrypter(key, encryption.AES256GCM)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, _ := enc.EncryptString("AES-GCM provides authentication for free")
	plaintext, _ := enc.DecryptString(ciphertext)

	fmt.Println(plaintext)
	// Output: AES-GCM provides authentication for free
}

// ExampleGenerateKey demonstrates generating keys for each supported cipher.
func ExampleGenerateKey() {
	ciphers := []encryption.Cipher{
		encryption.AES128CBC,
		encryption.AES256CBC,
		encryption.AES128GCM,
		encryption.AES256GCM,
	}
	for _, c := range ciphers {
		key, _ := encryption.GenerateKey(c)
		fmt.Printf("%s: %d bytes\n", c, len(key))
	}
	// Output:
	// aes-128-cbc: 16 bytes
	// aes-256-cbc: 32 bytes
	// aes-128-gcm: 16 bytes
	// aes-256-gcm: 32 bytes
}

// ExampleEncrypter_interface shows using the Encrypter interface for dependency
// injection, enabling callers to swap CBC for GCM (or a custom backend) without
// changing application code.
func ExampleEncrypter_interface() {
	encrypt := func(enc encryption.Encrypter, msg string) string {
		ct, _ := enc.EncryptString(msg)
		return ct
	}
	decrypt := func(enc encryption.Encrypter, ct string) string {
		pt, _ := enc.DecryptString(ct)
		return pt
	}

	// Use CBC.
	cbcKey, _ := encryption.GenerateKey(encryption.AES256CBC)
	cbcEnc, _ := encryption.NewEncrypter(cbcKey, encryption.AES256CBC)
	ct := encrypt(cbcEnc, "interface demo")
	fmt.Println(decrypt(cbcEnc, ct))

	// Use GCM — same calling code.
	gcmKey, _ := encryption.GenerateKey(encryption.AES256GCM)
	gcmEnc, _ := encryption.NewGCMEncrypter(gcmKey, encryption.AES256GCM)
	ct = encrypt(gcmEnc, "interface demo")
	fmt.Println(decrypt(gcmEnc, ct))

	// Output:
	// interface demo
	// interface demo
}
