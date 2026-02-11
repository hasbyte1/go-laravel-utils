package collections

// Enumerable is the interface satisfied by [Collection][T].
//
// Accept Enumerable in your own functions and interfaces so that consumers
// can substitute alternative implementations without depending on the
// concrete *Collection type.
//
// A minimal implementation only needs to provide these methods; all higher-
// level Collection helpers are built on top of this surface.
//
// Portability note: this maps to an Iterator protocol in Python
// (with __iter__/__next__) or an Iterable interface in Java/TypeScript.
type Enumerable[T any] interface {
	// All returns a copy of every item as a plain Go slice.
	All() []T

	// Count returns the number of items.
	Count() int

	// Each calls fn(item, index) for every item.
	Each(fn func(T, int))

	// Filter returns a new collection containing only items for which
	// fn returns true.
	Filter(fn func(T, int) bool) *Collection[T]

	// First returns the first item, optionally matching fns[0].
	// Returns the zero value and false when the collection is empty or
	// no item matches.
	First(fns ...func(T) bool) (T, bool)

	// IsEmpty reports whether the collection contains no items.
	IsEmpty() bool

	// IsNotEmpty reports whether the collection contains at least one item.
	IsNotEmpty() bool

	// Last returns the last item, optionally matching fns[0].
	// Returns the zero value and false when the collection is empty or
	// no item matches.
	Last(fns ...func(T) bool) (T, bool)

	// Reject returns a new collection with items for which fn returns
	// true removed.
	Reject(fn func(T, int) bool) *Collection[T]

	// ToSlice is an alias for All.
	ToSlice() []T
}
