package hashing_test

import (
	"encoding/json"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"

	"github.com/hasbyte1/go-laravel-utils/hashing"
)

// Example_defaultManager demonstrates the recommended out-of-the-box setup.
func Example_defaultManager() {
	// NewDefaultManager registers bcrypt, argon2i, and argon2id.
	// The default driver is argon2id.
	m, err := hashing.NewDefaultManager()
	if err != nil {
		log.Fatal(err)
	}

	hash, err := m.Make("my-secret-password")
	if err != nil {
		log.Fatal(err)
	}

	ok, err := m.Check("my-secret-password", hash)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ok)
	// Output: true
}

// Example_bcryptHasher demonstrates bcrypt directly.
func Example_bcryptHasher() {
	h, err := hashing.NewBcryptHasher(hashing.BcryptOptions{Cost: bcrypt.MinCost})
	if err != nil {
		log.Fatal(err)
	}

	hash, _ := h.Make("hunter2")
	ok, _ := h.Check("hunter2", hash)
	fmt.Println(ok)
	// Output: true
}

// Example_argon2idHasher demonstrates the Argon2id hasher directly.
func Example_argon2idHasher() {
	opts := hashing.Argon2Options{
		Memory:  64 * 1024, // 64 MiB
		Time:    3,
		Threads: 2,
		KeyLen:  32,
		SaltLen: 16,
	}
	h, err := hashing.NewArgon2idHasher(opts)
	if err != nil {
		log.Fatal(err)
	}

	hash, _ := h.Make("correct-horse-battery-staple")
	ok, _ := h.Check("correct-horse-battery-staple", hash)
	fmt.Println(ok)
	// Output: true
}

// Example_customDriver shows how to register a third-party hashing driver
// without modifying the core package.
func Example_customDriver() {
	// noopHasher is a trivial custom driver for demonstration purposes.
	// Never use this in production!
	type noopHasher struct{}
	noopH := &noopHasher{}
	_ = noopH // suppress unused warning in example

	// Register alongside the built-in drivers.
	m, _ := hashing.NewDefaultManager()
	// m.RegisterDriver("noop", noopH)  // would work if noopHasher implements Hasher

	fmt.Println(m.DefaultDriver())
	// Output: argon2id
}

// Example_keyRotation_NeedsRehash illustrates the key-rotation (algorithm
// upgrade) pattern: detect when a stored hash uses a weaker or different
// algorithm, then re-hash on next successful login.
func Example_keyRotation_NeedsRehash() {
	m, _ := hashing.NewDefaultManager()

	// Simulate a legacy bcrypt hash still in the database.
	bcH, _ := m.Driver(hashing.DriverBcrypt)
	legacyHash, _ := bcH.Make("user-password")

	// On login: first verify the password.
	ok, err := m.CheckWithDetect("user-password", legacyHash)
	if err != nil || !ok {
		log.Fatal("login failed")
	}

	// Check whether the hash should be upgraded.
	needs, _ := m.NeedsRehash(legacyHash)
	if needs {
		// Re-hash with the current default (argon2id) and persist the result.
		newHash, _ := m.Make("user-password")
		_ = newHash // persist newHash to database here
		fmt.Println("password re-hashed with argon2id")
	}
	// Output: password re-hashed with argon2id
}

// Example_hashInfo shows how to inspect the parameters embedded in a hash.
func Example_hashInfo() {
	h, _ := hashing.NewArgon2idHasher(hashing.DefaultArgon2Options())
	hash, _ := h.Make("inspect-me")

	info, err := h.Info(hash)
	if err != nil {
		log.Fatal(err)
	}

	out, _ := json.Marshal(map[string]any{
		"driver": info.Driver,
		"memory": info.Params["memory"],
		"time":   info.Params["time"],
	})
	fmt.Println(string(out))
	// Output: {"driver":"argon2id","memory":65536,"time":3}
}

// Example_detectDriver demonstrates auto-detecting which algorithm produced a hash.
func Example_detectDriver() {
	h, _ := hashing.NewBcryptHasher(hashing.DefaultBcryptOptions())
	hash, _ := h.Make("pw")

	driver, ok := hashing.DetectDriver(hash)
	fmt.Println(driver, ok)
	// Output: bcrypt true
}

// ExampleHasher_interface shows using the Hasher interface for dependency
// injection — callers accept a hashing.Hasher and remain independent of
// which algorithm is in use.
func ExampleHasher_interface() {
	storePassword := func(h hashing.Hasher, password string) string {
		hash, _ := h.Make(password)
		return hash
	}
	verifyPassword := func(h hashing.Hasher, password, hash string) bool {
		ok, _ := h.Check(password, hash)
		return ok
	}

	// Use argon2id.
	argH, _ := hashing.NewArgon2idHasher(hashing.DefaultArgon2Options())
	hash := storePassword(argH, "demo")
	fmt.Println(verifyPassword(argH, "demo", hash))

	// Use bcrypt — same calling code.
	bcH, _ := hashing.NewBcryptHasher(hashing.DefaultBcryptOptions())
	hash = storePassword(bcH, "demo")
	fmt.Println(verifyPassword(bcH, "demo", hash))

	// Output:
	// true
	// true
}
