package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ──────────────────────────────────────────────────────────────────────────────
// Options
// ──────────────────────────────────────────────────────────────────────────────

const (
	// DefaultArgon2Memory is the default memory cost in KiB (64 MiB).
	// OWASP ASVS Level 2 requires ≥ 19 MiB; 64 MiB is the standard production
	// recommendation for Argon2id.
	DefaultArgon2Memory uint32 = 64 * 1024

	// DefaultArgon2Time is the default number of iterations.
	DefaultArgon2Time uint32 = 3

	// DefaultArgon2Threads is the default degree of parallelism.
	DefaultArgon2Threads uint8 = 2

	// DefaultArgon2KeyLen is the default output key length in bytes.
	DefaultArgon2KeyLen uint32 = 32

	// DefaultArgon2SaltLen is the default random salt length in bytes.
	DefaultArgon2SaltLen uint32 = 16

	// argon2Version is the Argon2 specification version encoded in hashes.
	argon2Version = argon2.Version // 0x13 = 19
)

// Argon2Options configures an [Argon2iHasher] or [Argon2idHasher].
//
// All parameters are directly encoded into the output hash string (PHC format),
// so changing them only affects newly produced hashes; existing hashes remain
// verifiable as long as the hasher struct is present.
//
// Portability note: these map 1-to-1 to the memory_cost, time_cost, and
// parallelism parameters of Python's passlib argon2 backend and Node.js's
// argon2 npm package.
type Argon2Options struct {
	// Memory is the memory cost in KiB.
	// Minimum: 8 * Threads.  Default: [DefaultArgon2Memory] (64 MiB).
	Memory uint32

	// Time is the number of passes over memory (iterations).
	// Minimum: 1.  Default: [DefaultArgon2Time] (3).
	Time uint32

	// Threads is the degree of parallelism.
	// Minimum: 1.  Default: [DefaultArgon2Threads] (2).
	Threads uint8

	// KeyLen is the length of the derived key in bytes.
	// Default: [DefaultArgon2KeyLen] (32).
	KeyLen uint32

	// SaltLen is the length of the random salt in bytes.
	// Minimum: 8.  Default: [DefaultArgon2SaltLen] (16).
	SaltLen uint32
}

// DefaultArgon2Options returns Argon2Options with the recommended defaults.
// These exceed OWASP ASVS Level 2 requirements.
func DefaultArgon2Options() Argon2Options {
	return Argon2Options{
		Memory:  DefaultArgon2Memory,
		Time:    DefaultArgon2Time,
		Threads: DefaultArgon2Threads,
		KeyLen:  DefaultArgon2KeyLen,
		SaltLen: DefaultArgon2SaltLen,
	}
}

func validateArgon2Options(opts Argon2Options) error {
	if opts.Time < 1 {
		return fmt.Errorf("%w: argon2 time must be ≥ 1, got %d", ErrInvalidOption, opts.Time)
	}
	if opts.Threads < 1 {
		return fmt.Errorf("%w: argon2 threads must be ≥ 1, got %d", ErrInvalidOption, opts.Threads)
	}
	if opts.Memory < 8*uint32(opts.Threads) {
		return fmt.Errorf("%w: argon2 memory (%d KiB) must be ≥ 8×threads (%d KiB)",
			ErrInvalidOption, opts.Memory, 8*uint32(opts.Threads))
	}
	if opts.KeyLen < 4 {
		return fmt.Errorf("%w: argon2 key_len must be ≥ 4, got %d", ErrInvalidOption, opts.KeyLen)
	}
	if opts.SaltLen < 8 {
		return fmt.Errorf("%w: argon2 salt_len must be ≥ 8, got %d", ErrInvalidOption, opts.SaltLen)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// PHC string format helpers
// ──────────────────────────────────────────────────────────────────────────────

// argon2Params holds parameters and raw values decoded from a PHC hash string.
type argon2Params struct {
	variant DriverName
	version uint32
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
	salt    []byte
	hash    []byte
}

// encodePHC serialises an Argon2 hash in PHC String Format:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt_base64>$<hash_base64>
//
// The base64 encoding uses the standard alphabet without padding (RFC 4648 §5
// without "=") — this is the convention used by most Argon2 reference
// implementations and is compatible with Python's passlib and Node.js argon2.
func encodePHC(variant DriverName, version, memory, time uint32, threads uint8, salt, hash []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		string(variant),
		version,
		memory,
		time,
		threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// decodePHC parses an Argon2 PHC hash string and returns its components.
//
// Expected format (6 dollar-delimited segments, first is empty):
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func decodePHC(encoded string) (*argon2Params, error) {
	// Split on "$"; the leading "$" produces an empty first element.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return nil, fmt.Errorf("%w: expected 5-segment PHC string, got %d segments",
			ErrInvalidHash, len(parts)-1)
	}

	// parts[1]: variant name
	var variant DriverName
	switch parts[1] {
	case string(DriverArgon2i):
		variant = DriverArgon2i
	case string(DriverArgon2id):
		variant = DriverArgon2id
	default:
		return nil, fmt.Errorf("%w: unknown argon2 variant %q", ErrInvalidHash, parts[1])
	}

	// parts[2]: "v=<version>"
	version, err := parseKV(parts[2], "v")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	// parts[3]: "m=<memory>,t=<time>,p=<threads>"
	kvs, err := parseParams(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	memory, ok1 := kvs["m"]
	time, ok2 := kvs["t"]
	threads64, ok3 := kvs["p"]
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("%w: missing m/t/p in parameter segment %q", ErrInvalidHash, parts[3])
	}

	// parts[4]: base64-encoded salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid salt base64: %v", ErrInvalidHash, err)
	}

	// parts[5]: base64-encoded hash
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hash base64: %v", ErrInvalidHash, err)
	}

	return &argon2Params{
		variant: variant,
		version: uint32(version),
		memory:  uint32(memory),
		time:    uint32(time),
		threads: uint8(threads64),
		keyLen:  uint32(len(hash)),
		salt:    salt,
		hash:    hash,
	}, nil
}

// parseKV parses a "key=value" string and returns the uint64 value.
func parseKV(s, key string) (uint64, error) {
	prefix := key + "="
	if !strings.HasPrefix(s, prefix) {
		return 0, fmt.Errorf("expected %q prefix in %q", prefix, s)
	}
	return strconv.ParseUint(s[len(prefix):], 10, 64)
}

// parseParams splits "m=65536,t=3,p=2" into a map.
func parseParams(s string) (map[string]uint64, error) {
	out := make(map[string]uint64)
	for _, kv := range strings.Split(s, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("malformed param %q", kv)
		}
		v, err := strconv.ParseUint(kv[eq+1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("non-numeric value in %q: %v", kv, err)
		}
		out[kv[:eq]] = v
	}
	return out, nil
}

// randomSalt returns n cryptographically random bytes.
func randomSalt(n uint32) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("hashing: argon2: failed to generate salt: %w", err)
	}
	return b, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Argon2iHasher
// ──────────────────────────────────────────────────────────────────────────────

// Argon2iHasher hashes passwords using the Argon2i algorithm.
//
// Argon2i uses data-independent memory access, making it resistant to
// side-channel attacks but slightly more vulnerable to time-memory trade-off
// attacks compared to Argon2id.  For most password-hashing use cases, prefer
// [Argon2idHasher].
//
// Output format: PHC string ($argon2i$v=19$m=…,t=…,p=…$<salt>$<hash>).
// This is compatible with Python's passlib (argon2-cffi) and Node.js argon2.
//
// # Thread safety
//
// Argon2iHasher is immutable after construction and safe for concurrent use.
type Argon2iHasher struct {
	opts Argon2Options
}

// NewArgon2iHasher constructs an Argon2iHasher with the given options.
// Use [DefaultArgon2Options] for recommended defaults.
func NewArgon2iHasher(opts Argon2Options) (*Argon2iHasher, error) {
	if err := validateArgon2Options(opts); err != nil {
		return nil, err
	}
	return &Argon2iHasher{opts: opts}, nil
}

// Driver returns [DriverArgon2i].
func (h *Argon2iHasher) Driver() DriverName { return DriverArgon2i }

// Options returns the current Argon2 parameter set.
func (h *Argon2iHasher) Options() Argon2Options { return h.opts }

// Make hashes password with Argon2i and returns a PHC-formatted string.
// A fresh random salt of the configured length is generated for each call.
func (h *Argon2iHasher) Make(password string) (string, error) {
	salt, err := randomSalt(h.opts.SaltLen)
	if err != nil {
		return "", err
	}
	key := argon2.Key(
		[]byte(password), salt,
		h.opts.Time, h.opts.Memory, h.opts.Threads, h.opts.KeyLen,
	)
	return encodePHC(DriverArgon2i, argon2Version,
		h.opts.Memory, h.opts.Time, h.opts.Threads, salt, key), nil
}

// Check verifies that password matches the Argon2i PHC hash.
// The parameters (memory, time, threads) are read from the hash string itself,
// so verification works correctly even when the hasher's options have changed.
func (h *Argon2iHasher) Check(password, hash string) (bool, error) {
	p, err := decodePHC(hash)
	if err != nil {
		return false, err
	}
	if p.variant != DriverArgon2i {
		return false, fmt.Errorf("%w: hash is %s, not argon2i", ErrAlgorithmMismatch, p.variant)
	}
	computed := argon2.Key([]byte(password), p.salt, p.time, p.memory, p.threads, p.keyLen)
	return subtle.ConstantTimeCompare(computed, p.hash) == 1, nil
}

// NeedsRehash returns true if any parameter stored in hash differs from the
// hasher's current configuration.
func (h *Argon2iHasher) NeedsRehash(hash string) (bool, error) {
	p, err := decodePHC(hash)
	if err != nil {
		return false, err
	}
	if p.variant != DriverArgon2i {
		return false, fmt.Errorf("%w: hash is %s, not argon2i", ErrAlgorithmMismatch, p.variant)
	}
	return p.memory != h.opts.Memory ||
		p.time != h.opts.Time ||
		p.threads != h.opts.Threads ||
		p.keyLen != h.opts.KeyLen, nil
}

// Info parses the PHC string and returns the encoded parameters.
//
// Returned [HashInfo].Params:
//   - "version" → int
//   - "memory"  → uint32 (KiB)
//   - "time"    → uint32
//   - "threads" → uint8
//   - "key_len" → uint32
func (h *Argon2iHasher) Info(hash string) (HashInfo, error) {
	return argon2Info(hash, DriverArgon2i)
}

// ──────────────────────────────────────────────────────────────────────────────
// Argon2idHasher
// ──────────────────────────────────────────────────────────────────────────────

// Argon2idHasher hashes passwords using the Argon2id algorithm.
//
// Argon2id is a hybrid of Argon2i and Argon2d.  It provides resistance to
// both side-channel attacks (first half of passes) and time-memory trade-off
// attacks (second half of passes), making it the recommended choice for
// password hashing according to RFC 9106 and OWASP.
//
// Output format: PHC string ($argon2id$v=19$m=…,t=…,p=…$<salt>$<hash>).
//
// # Thread safety
//
// Argon2idHasher is immutable after construction and safe for concurrent use.
type Argon2idHasher struct {
	opts Argon2Options
}

// NewArgon2idHasher constructs an Argon2idHasher with the given options.
// Use [DefaultArgon2Options] for recommended defaults.
func NewArgon2idHasher(opts Argon2Options) (*Argon2idHasher, error) {
	if err := validateArgon2Options(opts); err != nil {
		return nil, err
	}
	return &Argon2idHasher{opts: opts}, nil
}

// Driver returns [DriverArgon2id].
func (h *Argon2idHasher) Driver() DriverName { return DriverArgon2id }

// Options returns the current Argon2 parameter set.
func (h *Argon2idHasher) Options() Argon2Options { return h.opts }

// Make hashes password with Argon2id and returns a PHC-formatted string.
// A fresh random salt of the configured length is generated for each call.
func (h *Argon2idHasher) Make(password string) (string, error) {
	salt, err := randomSalt(h.opts.SaltLen)
	if err != nil {
		return "", err
	}
	key := argon2.IDKey(
		[]byte(password), salt,
		h.opts.Time, h.opts.Memory, h.opts.Threads, h.opts.KeyLen,
	)
	return encodePHC(DriverArgon2id, argon2Version,
		h.opts.Memory, h.opts.Time, h.opts.Threads, salt, key), nil
}

// Check verifies that password matches the Argon2id PHC hash.
func (h *Argon2idHasher) Check(password, hash string) (bool, error) {
	p, err := decodePHC(hash)
	if err != nil {
		return false, err
	}
	if p.variant != DriverArgon2id {
		return false, fmt.Errorf("%w: hash is %s, not argon2id", ErrAlgorithmMismatch, p.variant)
	}
	computed := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, p.keyLen)
	return subtle.ConstantTimeCompare(computed, p.hash) == 1, nil
}

// NeedsRehash returns true if any parameter stored in hash differs from the
// hasher's current configuration.
func (h *Argon2idHasher) NeedsRehash(hash string) (bool, error) {
	p, err := decodePHC(hash)
	if err != nil {
		return false, err
	}
	if p.variant != DriverArgon2id {
		return false, fmt.Errorf("%w: hash is %s, not argon2id", ErrAlgorithmMismatch, p.variant)
	}
	return p.memory != h.opts.Memory ||
		p.time != h.opts.Time ||
		p.threads != h.opts.Threads ||
		p.keyLen != h.opts.KeyLen, nil
}

// Info parses the PHC string and returns the encoded parameters.
func (h *Argon2idHasher) Info(hash string) (HashInfo, error) {
	return argon2Info(hash, DriverArgon2id)
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────────────────

// argon2Info is the shared Info implementation for both Argon2 variants.
func argon2Info(hash string, expected DriverName) (HashInfo, error) {
	p, err := decodePHC(hash)
	if err != nil {
		return HashInfo{}, err
	}
	if p.variant != expected {
		return HashInfo{}, fmt.Errorf("%w: hash is %s, not %s", ErrAlgorithmMismatch, p.variant, expected)
	}
	return HashInfo{
		Driver: p.variant,
		Params: map[string]any{
			"version": int(p.version),
			"memory":  p.memory,
			"time":    p.time,
			"threads": p.threads,
			"key_len": p.keyLen,
		},
	}, nil
}
