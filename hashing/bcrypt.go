package hashing

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultBcryptCost is the recommended work factor for bcrypt.
	// At cost 12, hashing takes approximately 250 ms on a modern server CPU,
	// which satisfies OWASP ASVS Level 1 (≥ 10) and Level 2 (≥ 12).
	//
	// Increase this value as hardware improves; aim to keep hashing time
	// between 100 ms and 500 ms for your deployment environment.
	DefaultBcryptCost = 12
)

// BcryptOptions configures a [BcryptHasher].
//
// Portability note: in Python pass cost as a keyword argument to your hasher
// constructor; in Node.js pass it as an options object.
type BcryptOptions struct {
	// Cost is the bcrypt work factor (logarithmic).
	// Valid range: [bcrypt.MinCost (4), bcrypt.MaxCost (31)].
	// Default: [DefaultBcryptCost] (12).
	Cost int
}

// DefaultBcryptOptions returns BcryptOptions with [DefaultBcryptCost].
func DefaultBcryptOptions() BcryptOptions {
	return BcryptOptions{Cost: DefaultBcryptCost}
}

// BcryptHasher hashes passwords using the bcrypt algorithm.
//
// Bcrypt internally generates and stores a 128-bit (16-byte) random salt,
// so callers never need to manage salts explicitly.
//
// # When to use bcrypt vs Argon2id
//
// Bcrypt is the battle-tested choice with the widest ecosystem support.
// Prefer [Argon2idHasher] for new systems — it allows tuning of memory cost,
// which makes GPU/ASIC attacks significantly more expensive.
//
// # Thread safety
//
// BcryptHasher is immutable after construction and safe for concurrent use.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher constructs a BcryptHasher with the provided options.
// Returns [ErrInvalidOption] if Cost is outside [bcrypt.MinCost, bcrypt.MaxCost].
func NewBcryptHasher(opts BcryptOptions) (*BcryptHasher, error) {
	if opts.Cost < bcrypt.MinCost || opts.Cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("%w: bcrypt cost %d must be in [%d, %d]",
			ErrInvalidOption, opts.Cost, bcrypt.MinCost, bcrypt.MaxCost)
	}
	return &BcryptHasher{cost: opts.Cost}, nil
}

// Driver returns [DriverBcrypt].
func (h *BcryptHasher) Driver() DriverName { return DriverBcrypt }

// Cost returns the configured bcrypt work factor.
func (h *BcryptHasher) Cost() int { return h.cost }

// Make hashes password with bcrypt and returns the Modular Crypt Format string
// (e.g., "$2b$12$...").  A fresh 128-bit random salt is generated internally.
//
// Security note: bcrypt truncates passwords longer than 72 bytes.  If you
// need to hash passwords longer than 72 bytes, pre-hash with SHA-256 or use
// an Argon2 driver.
func (h *BcryptHasher) Make(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("hashing: bcrypt: failed to hash password: %w", err)
	}
	return string(hash), nil
}

// Check verifies that password matches the bcrypt-encoded hash.
// Returns (false, nil) on mismatch; never returns ErrMismatchedHashAndPassword.
func (h *BcryptHasher) Check(password, hash string) (bool, error) {
	if !h.looksLikeBcrypt(hash) {
		return false, fmt.Errorf("%w: hash does not appear to be bcrypt", ErrAlgorithmMismatch)
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("hashing: bcrypt: %w", err)
	}
	return true, nil
}

// NeedsRehash returns true if the work factor encoded in hash differs from
// the hasher's configured cost.  A lower stored cost means the hash is less
// secure than the current configuration; a higher stored cost means the
// configuration was intentionally dialled back (rare but handled).
func (h *BcryptHasher) NeedsRehash(hash string) (bool, error) {
	if !h.looksLikeBcrypt(hash) {
		return false, fmt.Errorf("%w: hash does not appear to be bcrypt", ErrAlgorithmMismatch)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	return cost != h.cost, nil
}

// Info extracts the work factor from a bcrypt hash string.
//
// Returned [HashInfo].Params:
//   - "cost" → int
func (h *BcryptHasher) Info(hash string) (HashInfo, error) {
	if !h.looksLikeBcrypt(hash) {
		return HashInfo{}, fmt.Errorf("%w: hash does not appear to be bcrypt", ErrAlgorithmMismatch)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return HashInfo{}, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	return HashInfo{
		Driver: DriverBcrypt,
		Params: map[string]any{"cost": cost},
	}, nil
}

// looksLikeBcrypt returns true if hash has a recognised bcrypt prefix.
func (h *BcryptHasher) looksLikeBcrypt(hash string) bool {
	d, ok := DetectDriver(hash)
	return ok && d == DriverBcrypt
}
