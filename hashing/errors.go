package hashing

import "errors"

// Sentinel errors returned by hashing operations.
//
// Use [errors.Is] for comparisons:
//
//	ok, err := hasher.Check(password, hash)
//	if errors.Is(err, hashing.ErrInvalidHash) {
//	    // hash string is malformed
//	}
var (
	// ErrInvalidHash is returned when a hash string cannot be parsed because
	// it has an unrecognised format, missing fields, or invalid encoding.
	ErrInvalidHash = errors.New("hashing: invalid or unrecognised hash string")

	// ErrInvalidOption is returned when a constructor is called with a
	// parameter value that falls outside the allowed range (e.g., a bcrypt
	// cost below 4 or above 31).
	ErrInvalidOption = errors.New("hashing: invalid option value")

	// ErrDriverNotFound is returned by [Manager.Driver] or indirectly by
	// [Manager.Make] / [Manager.Check] when the requested driver has not been
	// registered.
	ErrDriverNotFound = errors.New("hashing: driver not found")

	// ErrEmptyDriverName is returned by [Manager.RegisterDriver] when the
	// supplied driver name is an empty string.
	ErrEmptyDriverName = errors.New("hashing: driver name must not be empty")

	// ErrNilHasher is returned by [Manager.RegisterDriver] when a nil [Hasher]
	// is supplied.
	ErrNilHasher = errors.New("hashing: hasher must not be nil")

	// ErrAlgorithmMismatch is returned by a [Hasher]'s Check or NeedsRehash
	// method when the hash string was produced by a different algorithm than
	// the one implemented by that hasher.
	ErrAlgorithmMismatch = errors.New("hashing: hash was produced by a different algorithm")
)
