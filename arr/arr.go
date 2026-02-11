package arr

import (
	"math/rand"
	"sort"
)

// ─────────────────────────────────────────────────────────────────────────────
// Searching & testing
// ─────────────────────────────────────────────────────────────────────────────

// First returns the first element, optionally matching fns[0].
// Returns the zero value and false when items is empty or no element matches.
func First[T any](items []T, fns ...func(T) bool) (T, bool) {
	var zero T
	if len(fns) > 0 {
		for _, item := range items {
			if fns[0](item) {
				return item, true
			}
		}
		return zero, false
	}
	if len(items) == 0 {
		return zero, false
	}
	return items[0], true
}

// Last returns the last element, optionally matching fns[0].
// Returns the zero value and false when items is empty or no element matches.
func Last[T any](items []T, fns ...func(T) bool) (T, bool) {
	var zero T
	if len(fns) > 0 {
		var found T
		matched := false
		for _, item := range items {
			if fns[0](item) {
				found = item
				matched = true
			}
		}
		return found, matched
	}
	if len(items) == 0 {
		return zero, false
	}
	return items[len(items)-1], true
}

// Contains reports whether at least one element satisfies fn.
func Contains[T any](items []T, fn func(T) bool) bool {
	for _, item := range items {
		if fn(item) {
			return true
		}
	}
	return false
}

// ContainsValue reports whether items contains value (requires comparable T).
func ContainsValue[T comparable](items []T, value T) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// IndexOf returns the index of the first occurrence of value, or -1.
func IndexOf[T comparable](items []T, value T) int {
	for i, item := range items {
		if item == value {
			return i
		}
	}
	return -1
}

// Search returns the index of the first element satisfying fn, or -1.
func Search[T any](items []T, fn func(T) bool) int {
	for i, item := range items {
		if fn(item) {
			return i
		}
	}
	return -1
}

// ─────────────────────────────────────────────────────────────────────────────
// Transformation
// ─────────────────────────────────────────────────────────────────────────────

// Map applies fn(item, index) to each element and returns a new slice.
func Map[T, U any](items []T, fn func(T, int) U) []U {
	out := make([]U, len(items))
	for i, item := range items {
		out[i] = fn(item, i)
	}
	return out
}

// Filter returns elements for which fn(item, index) returns true.
func Filter[T any](items []T, fn func(T, int) bool) []T {
	out := make([]T, 0, len(items))
	for i, item := range items {
		if fn(item, i) {
			out = append(out, item)
		}
	}
	return out
}

// Reject returns elements for which fn returns false.
func Reject[T any](items []T, fn func(T, int) bool) []T {
	return Filter(items, func(item T, i int) bool { return !fn(item, i) })
}

// Reduce reduces items to a single value of type U.
func Reduce[T, U any](items []T, fn func(U, T, int) U, initial U) U {
	result := initial
	for i, item := range items {
		result = fn(result, item, i)
	}
	return result
}

// FlatMap applies fn to each element (producing a []U) and flattens the results.
func FlatMap[T, U any](items []T, fn func(T, int) []U) []U {
	out := make([]U, 0, len(items))
	for i, item := range items {
		out = append(out, fn(item, i)...)
	}
	return out
}

// Pluck extracts a value of type U from each element of type T.
func Pluck[T, U any](items []T, fn func(T) U) []U {
	out := make([]U, len(items))
	for i, item := range items {
		out[i] = fn(item)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Set operations
// ─────────────────────────────────────────────────────────────────────────────

// Unique returns a new slice with consecutive and non-consecutive duplicates
// removed, preserving the first occurrence (requires comparable T).
func Unique[T comparable](items []T) []T {
	seen := make(map[T]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

// UniqueBy returns elements with duplicates removed using a key function.
func UniqueBy[T any, K comparable](items []T, fn func(T) K) []T {
	seen := make(map[K]struct{}, len(items))
	out := make([]T, 0, len(items))
	for _, item := range items {
		k := fn(item)
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

// Diff returns elements in a that are not in b (requires comparable T).
func Diff[T comparable](a, b []T) []T {
	set := make(map[T]struct{}, len(b))
	for _, item := range b {
		set[item] = struct{}{}
	}
	out := make([]T, 0)
	for _, item := range a {
		if _, found := set[item]; !found {
			out = append(out, item)
		}
	}
	return out
}

// Intersect returns elements that appear in both a and b (requires comparable T).
func Intersect[T comparable](a, b []T) []T {
	set := make(map[T]struct{}, len(b))
	for _, item := range b {
		set[item] = struct{}{}
	}
	out := make([]T, 0)
	for _, item := range a {
		if _, found := set[item]; found {
			out = append(out, item)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Slicing & Restructuring
// ─────────────────────────────────────────────────────────────────────────────

// Chunk splits items into consecutive groups of size.
// The last group may contain fewer than size elements.
func Chunk[T any](items []T, size int) [][]T {
	if size <= 0 || len(items) == 0 {
		return [][]T{}
	}
	chunks := make([][]T, 0, (len(items)+size-1)/size)
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunk := make([]T, end-i)
		copy(chunk, items[i:end])
		chunks = append(chunks, chunk)
	}
	return chunks
}

// Collapse flattens a slice of slices into a single flat slice.
func Collapse[T any](items [][]T) []T {
	total := 0
	for _, chunk := range items {
		total += len(chunk)
	}
	out := make([]T, 0, total)
	for _, chunk := range items {
		out = append(out, chunk...)
	}
	return out
}

// Flatten recursively flattens any nested []any structure.
func Flatten(items any) []any {
	out := make([]any, 0)
	var flatten func(v any)
	flatten = func(v any) {
		switch val := v.(type) {
		case []any:
			for _, elem := range val {
				flatten(elem)
			}
		default:
			out = append(out, val)
		}
	}
	flatten(items)
	return out
}

// Reverse returns a reversed copy of items.
func Reverse[T any](items []T) []T {
	n := len(items)
	out := make([]T, n)
	for i, item := range items {
		out[n-1-i] = item
	}
	return out
}

// Prepend prepends values to the front of items.
func Prepend[T any](items []T, values ...T) []T {
	out := make([]T, len(values)+len(items))
	copy(out, values)
	copy(out[len(values):], items)
	return out
}

// Wrap wraps value in a slice. If value is nil (pointer or interface), an
// empty slice is returned.
func Wrap[T any](value T) []T {
	return []T{value}
}

// Partition splits items into two slices: those satisfying fn and those that do not.
func Partition[T any](items []T, fn func(T) bool) ([]T, []T) {
	pass := make([]T, 0)
	fail := make([]T, 0)
	for _, item := range items {
		if fn(item) {
			pass = append(pass, item)
		} else {
			fail = append(fail, item)
		}
	}
	return pass, fail
}

// Zip combines two slices element-by-element into pairs.
// Stops at the length of the shorter slice.
type Pair[A, B any] struct {
	First  A
	Second B
}

// Zip pairs elements from a and b at the same index.
func Zip[A, B any](a []A, b []B) []Pair[A, B] {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]Pair[A, B], n)
	for i := 0; i < n; i++ {
		out[i] = Pair[A, B]{First: a[i], Second: b[i]}
	}
	return out
}

// Combine creates a map from equal-length key and value slices.
// Returns an error if lengths differ.
func Combine[K comparable, V any](keys []K, values []V) (map[K]V, error) {
	if len(keys) != len(values) {
		return nil, errMismatchedLengths
	}
	out := make(map[K]V, len(keys))
	for i, k := range keys {
		out[k] = values[i]
	}
	return out, nil
}

// GroupBy groups items by a comparable key K extracted by fn.
func GroupBy[T any, K comparable](items []T, fn func(T) K) map[K][]T {
	groups := make(map[K][]T)
	for _, item := range items {
		k := fn(item)
		groups[k] = append(groups[k], item)
	}
	return groups
}

// KeyBy creates a map[K]T from items keyed by fn.
// When multiple items share the same key, the last one wins.
func KeyBy[T any, K comparable](items []T, fn func(T) K) map[K]T {
	out := make(map[K]T, len(items))
	for _, item := range items {
		out[fn(item)] = item
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Sorting & Randomisation
// ─────────────────────────────────────────────────────────────────────────────

// Sort returns a sorted copy of items using less.
func Sort[T any](items []T, less func(a, b T) bool) []T {
	out := make([]T, len(items))
	copy(out, items)
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// Shuffle returns a randomly shuffled copy of items.
func Shuffle[T any](items []T) []T {
	out := make([]T, len(items))
	copy(out, items)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Random returns n randomly selected items (without replacement).
// If n >= len(items), a shuffled copy of all items is returned.
func Random[T any](items []T, n int) []T {
	s := Shuffle(items)
	if n >= len(s) {
		return s
	}
	return s[:n]
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregation
// ─────────────────────────────────────────────────────────────────────────────

// Sum returns the sum of items via fn.
func Sum[T any](items []T, fn func(T) float64) float64 {
	var total float64
	for _, item := range items {
		total += fn(item)
	}
	return total
}

// Min returns the element with the smallest value extracted by fn.
// Returns the zero value and false if items is empty.
func Min[T any](items []T, fn func(T) float64) (T, bool) {
	var zero T
	if len(items) == 0 {
		return zero, false
	}
	minItem, minVal := items[0], fn(items[0])
	for _, item := range items[1:] {
		if v := fn(item); v < minVal {
			minVal, minItem = v, item
		}
	}
	return minItem, true
}

// Max returns the element with the largest value extracted by fn.
// Returns the zero value and false if items is empty.
func Max[T any](items []T, fn func(T) float64) (T, bool) {
	var zero T
	if len(items) == 0 {
		return zero, false
	}
	maxItem, maxVal := items[0], fn(items[0])
	for _, item := range items[1:] {
		if v := fn(item); v > maxVal {
			maxVal, maxItem = v, item
		}
	}
	return maxItem, true
}
