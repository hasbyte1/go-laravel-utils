package collections

// This file contains package-level generic functions for operations that
// transform a Collection[T] to a Collection[U] (T ≠ U).
//
// Go generics do not allow methods to introduce their own type parameters, so
// these operations must be stand-alone functions. They are designed to be
// composable with method-chaining calls:
//
//	result := collections.Map(
//	    collections.New(1, 2, 3, 4, 5).Filter(func(n, _ int) bool { return n%2 == 0 }),
//	    func(n, _ int) string { return strconv.Itoa(n) },
//	)

// Map applies fn to every item and returns a new Collection[U].
//
//	doubled := collections.Map(collections.New(1, 2, 3),
//	    func(n, _ int) string { return strconv.Itoa(n * 2) })
func Map[T, U any](c *Collection[T], fn func(T, int) U) *Collection[U] {
	out := make([]U, len(c.items))
	for i, item := range c.items {
		out[i] = fn(item, i)
	}
	return &Collection[U]{items: out}
}

// FlatMap applies fn to every item (producing a []U per item) and flattens
// the results into a single Collection[U].
//
//	words := collections.FlatMap(collections.New("hello world", "foo bar"),
//	    func(s string, _ int) []string { return strings.Fields(s) })
//	// → ["hello", "world", "foo", "bar"]
func FlatMap[T, U any](c *Collection[T], fn func(T, int) []U) *Collection[U] {
	out := make([]U, 0, len(c.items))
	for i, item := range c.items {
		out = append(out, fn(item, i)...)
	}
	return &Collection[U]{items: out}
}

// Reduce reduces Collection[T] to a single value of type U.
//
//	sum := collections.Reduce(collections.New(1, 2, 3, 4),
//	    func(acc int, n, _ int) int { return acc + n }, 0)
func Reduce[T, U any](c *Collection[T], fn func(U, T, int) U, initial U) U {
	result := initial
	for i, item := range c.items {
		result = fn(result, item, i)
	}
	return result
}

// Pluck extracts a single field U from every item T and returns a new
// Collection[U].
//
//	names := collections.Pluck(users, func(u User) string { return u.Name })
func Pluck[T, U any](c *Collection[T], fn func(T) U) *Collection[U] {
	out := make([]U, len(c.items))
	for i, item := range c.items {
		out[i] = fn(item)
	}
	return &Collection[U]{items: out}
}

// GroupBy groups items by the comparable key K extracted by fn.
//
//	byDept := collections.GroupBy(employees,
//	    func(e Employee) string { return e.Department })
func GroupBy[T any, K comparable](c *Collection[T], fn func(T) K) map[K]*Collection[T] {
	groups := make(map[K]*Collection[T])
	for _, item := range c.items {
		k := fn(item)
		if groups[k] == nil {
			groups[k] = Empty[T]()
		}
		groups[k].items = append(groups[k].items, item)
	}
	return groups
}

// KeyBy builds a map[K]T keyed by the value extracted by fn.
// When multiple items share the same key, the last one wins.
//
//	byID := collections.KeyBy(users, func(u User) int { return u.ID })
func KeyBy[T any, K comparable](c *Collection[T], fn func(T) K) map[K]T {
	out := make(map[K]T, len(c.items))
	for _, item := range c.items {
		out[fn(item)] = item
	}
	return out
}

// Zip combines two collections element-by-element into Pairs.
// Stops at the shorter of the two collections.
//
//	pairs := collections.Zip(
//	    collections.New("a", "b", "c"),
//	    collections.New(1, 2, 3),
//	) // → [(a,1), (b,2), (c,3)]
func Zip[A, B any](a *Collection[A], b *Collection[B]) *Collection[Pair[A, B]] {
	n := len(a.items)
	if len(b.items) < n {
		n = len(b.items)
	}
	out := make([]Pair[A, B], n)
	for i := 0; i < n; i++ {
		out[i] = Pair[A, B]{First: a.items[i], Second: b.items[i]}
	}
	return &Collection[Pair[A, B]]{items: out}
}

// Combine creates a map from equal-length key and value slices.
// Returns [ErrMismatchedLengths] if len(keys) != len(values).
//
//	m, _ := collections.Combine([]string{"a", "b"}, []int{1, 2})
//	// → map["a":1, "b":2]
func Combine[K comparable, V any](keys []K, values []V) (map[K]V, error) {
	if len(keys) != len(values) {
		return nil, ErrMismatchedLengths
	}
	out := make(map[K]V, len(keys))
	for i, k := range keys {
		out[k] = values[i]
	}
	return out, nil
}

// Collapse flattens a Collection[[]T] into a Collection[T] (one level only).
//
//	flat := collections.Collapse(collections.New([]int{1, 2}, []int{3, 4}))
//	// → [1, 2, 3, 4]
func Collapse[T any](c *Collection[[]T]) *Collection[T] {
	total := 0
	for _, chunk := range c.items {
		total += len(chunk)
	}
	out := make([]T, 0, total)
	for _, chunk := range c.items {
		out = append(out, chunk...)
	}
	return &Collection[T]{items: out}
}

// Flatten is an alias for [Collapse] — it flattens one level of nesting.
func Flatten[T any](c *Collection[[]T]) *Collection[T] { return Collapse(c) }

// FlattenDeep recursively flattens a Collection[any] that may contain nested
// slices or *Collection[any] values of arbitrary depth.
//
// The result type is Collection[any]; use type assertions on individual
// elements as needed.
func FlattenDeep(c *Collection[any]) *Collection[any] {
	out := make([]any, 0, len(c.items))
	var flatten func(items []any)
	flatten = func(items []any) {
		for _, item := range items {
			switch v := item.(type) {
			case []any:
				flatten(v)
			case *Collection[any]:
				flatten(v.items)
			default:
				out = append(out, item)
			}
		}
	}
	flatten(c.items)
	return &Collection[any]{items: out}
}
