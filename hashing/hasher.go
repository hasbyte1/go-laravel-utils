// Package hashing provides extensible, framework-agnostic password hashing
// modelled after Laravel's Illuminate/Hashing module.
//
// # Architecture
//
// The central abstraction is the [Hasher] interface.  Three drivers ship with
// this package: [BcryptHasher], [Argon2iHasher], and [Argon2idHasher].  All
// implement [Hasher], so callers can depend on the interface rather than a
// concrete type — the strategy pattern.
//
// The [Manager] is a driver registry and dispatcher.  Register named [Hasher]
// implementations, designate one as the default, then delegate all hashing
// operations through the [Manager].  This mirrors Laravel's HashManager and
// translates cleanly to a driver map / factory in Python or Node.js.
//
// # Quick start
//
//	m, err := hashing.NewDefaultManager()   // Argon2id default, all drivers registered
//	if err != nil { log.Fatal(err) }
//
//	hash, _ := m.Make("my-secret-password")
//	ok,   _ := m.Check("my-secret-password", hash)
//
// # Security defaults
//
//   - bcrypt:  cost 12 (≈ 250 ms on modern hardware; exceeds OWASP minimum of 10).
//   - Argon2id: m=64 MiB, t=3 iterations, p=2 threads, 32-byte key.
//     Exceeds OWASP ASVS Level 2 (m≥19 MiB, t≥2, p≥1).
//   - Argon2i:  same defaults as Argon2id (use Argon2id for new systems).
//
// # Portability
//
// The [Hasher] interface maps 1-to-1 to class methods in Python and Node.js.
// See the package README for skeleton ports in both languages.
package hashing

import "strings"

// DriverName identifies a hashing algorithm driver.
// Using a named string type prevents accidental confusion with plain strings.
type DriverName string

const (
	// DriverBcrypt selects the bcrypt driver.
	DriverBcrypt DriverName = "bcrypt"
	// DriverArgon2i selects the Argon2i driver.
	DriverArgon2i DriverName = "argon2i"
	// DriverArgon2id selects the Argon2id driver (recommended for new systems).
	DriverArgon2id DriverName = "argon2id"
)

// Hasher is the core interface satisfied by all password-hashing drivers.
//
// All implementations must be safe for concurrent use by multiple goroutines.
//
// # Portability note
//
// This interface maps directly to instance methods in Python (class) and
// Node.js (class / object).  The only Go-specific idiom is returning an
// error value alongside the result; other languages should raise / throw on
// failure instead.  Example equivalents:
//
//	Python:  def make(self, password: str) -> str
//	Node.js: make(password: string): Promise<string>
type Hasher interface {
	// Make hashes a plaintext password and returns the encoded hash string.
	// A fresh cryptographic salt is generated for every call, so two calls
	// with the same password will produce different outputs.
	Make(password string) (string, error)

	// Check verifies that password matches the previously encoded hash.
	// Returns (true, nil) on match, (false, nil) on mismatch, or
	// (false, err) if the hash is structurally invalid.
	//
	// Comparison is performed in constant time to prevent timing attacks.
	Check(password, hash string) (bool, error)

	// NeedsRehash returns true when the hash was produced with parameters
	// that are weaker than — or simply different from — the hasher's current
	// configuration.  Callers should re-hash the password on next successful
	// login when this returns true.
	NeedsRehash(hash string) (bool, error)

	// Info extracts metadata from an encoded hash string without verifying it.
	// Useful for auditing, migration tooling, or logging.
	Info(hash string) (HashInfo, error)

	// Driver returns the DriverName implemented by this hasher.
	Driver() DriverName
}

// HashInfo carries metadata parsed from an encoded hash string.
//
// Portability note: in Python this would be a dataclass; in Node.js a plain
// object or a class with named fields.
type HashInfo struct {
	// Driver is the hashing algorithm that produced the hash.
	Driver DriverName

	// Params holds algorithm-specific parameters extracted from the hash string.
	//
	// For bcrypt:
	//   "cost" → int
	//
	// For Argon2i and Argon2id:
	//   "version" → int   (Argon2 version number, typically 19)
	//   "memory"  → uint32 (KiB)
	//   "time"    → uint32 (iterations)
	//   "threads" → uint8  (degree of parallelism)
	//   "key_len" → uint32 (output key length in bytes)
	Params map[string]any
}

// DetectDriver inspects a hash string and returns the [DriverName] that
// produced it.  It is a best-effort heuristic based on the hash prefix and
// does not verify the hash itself.
//
// The second return value is false when the hash format is not recognised.
func DetectDriver(hash string) (DriverName, bool) {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return DriverArgon2id, true
	case strings.HasPrefix(hash, "$argon2i$"):
		return DriverArgon2i, true
	// bcrypt hashes start with $2a$, $2b$, or $2y$
	case strings.HasPrefix(hash, "$2a$"),
		strings.HasPrefix(hash, "$2b$"),
		strings.HasPrefix(hash, "$2y$"):
		return DriverBcrypt, true
	default:
		return "", false
	}
}
