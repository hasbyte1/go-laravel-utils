package collections

import "errors"

// Sentinel errors returned by Collection and Arr operations.
var (
	// ErrEmptyCollection is returned when an operation requires at least one
	// element but the collection is empty.
	ErrEmptyCollection = errors.New("collections: operation on empty collection")

	// ErrIndexOutOfRange is returned when an index is outside [0, Count()-1].
	ErrIndexOutOfRange = errors.New("collections: index out of range")

	// ErrNoMatchingItems is returned by FirstOrFail / LastOrFail when no
	// item satisfies the predicate.
	ErrNoMatchingItems = errors.New("collections: no items match the given condition")

	// ErrInvalidChunkSize is returned when Chunk is called with size <= 0.
	ErrInvalidChunkSize = errors.New("collections: chunk size must be greater than 0")

	// ErrMismatchedLengths is returned by Combine when the key and value
	// slices have different lengths.
	ErrMismatchedLengths = errors.New("collections: keys and values must have the same length")

	// ErrMacroNotFound is returned when an unregistered macro name is called.
	ErrMacroNotFound = errors.New("collections: macro not found")
)
