// Package hashing provides extensible, framework-agnostic password hashing
// modelled after Laravel's Illuminate/Hashing module.
//
// # Architecture
//
// The central abstraction is the [Hasher] interface. Three drivers ship with
// this package:
//
//   - [BcryptHasher] — bcrypt (recommended for compatibility; widest ecosystem support)
//   - [Argon2iHasher] — Argon2i (memory-hard; use Argon2id for new systems)
//   - [Argon2idHasher] — Argon2id (recommended for new systems; resists side-channel attacks)
//
// All three implement [Hasher], so callers can depend on the interface rather
// than a concrete type — the strategy pattern.
//
// The [Manager] is a named driver registry and dispatcher, equivalent to
// Laravel's HashManager. Register one or more [Hasher] implementations,
// designate a default driver, then delegate all hashing operations through
// the [Manager].
//
// # Quick start
//
//	m, err := hashing.NewDefaultManager() // Argon2id default, all drivers registered
//	if err != nil { log.Fatal(err) }
//
//	hash, _ := m.Make("my-secret-password")
//	ok, _   := m.Check("my-secret-password", hash) // true
//
// # Security defaults
//
//   - bcrypt:  cost 12 (≈ 250 ms on modern hardware; exceeds OWASP minimum of 10).
//   - Argon2id: m=64 MiB, t=3 iterations, p=2 threads, 32-byte key.
//     Exceeds OWASP ASVS Level 2 (m≥19 MiB, t≥2, p≥1).
//
// # Cross-driver migration
//
// Call [Manager.NeedsRehash] on every successful login. It returns true when
// the stored hash was produced by a different driver or with weaker parameters
// than the current default. Re-hash and persist immediately:
//
//	ok, _ := m.CheckWithDetect(password, storedHash)
//	if ok {
//	    if needs, _ := m.NeedsRehash(storedHash); needs {
//	        newHash, _ := m.Make(password)
//	        persist(userID, newHash)
//	    }
//	}
//
// # Argon2 hash format
//
// Argon2 hashes are stored in the PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
//
// All parameters are self-contained in the string, so no external configuration
// is needed to verify a previously produced hash.
//
// # Portability
//
// The [Hasher] interface maps 1-to-1 to class methods in Python and Node.js.
// See the repository README for porting notes.
package hashing
