package collections

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
)

// Collection is a generic, immutable-by-default wrapper around a slice of T.
//
// Every method that transforms the collection returns a *new* Collection,
// leaving the original unchanged. This design is goroutine-safe for reads
// (multiple goroutines may read the same collection concurrently) and avoids
// accidental aliasing bugs in pipelines.
//
// # Creating a collection
//
//	c := collections.New(1, 2, 3, 4, 5)
//	c := collections.From([]string{"a", "b", "c"})
//	c := collections.Empty[int]()
//
// # Method chaining
//
//	result := collections.New(1, 2, 3, 4, 5, 6).
//	    Filter(func(n int, _ int) bool { return n%2 == 0 }).
//	    SortBy(func(n int) float64 { return float64(n) }).
//	    Take(2)
//
// # Type-transforming operations
//
// Go generics do not allow methods to introduce new type parameters.
// Operations that change the element type are exposed as package-level
// functions in this package:
//
//	doubled := collections.Map(c, func(n int, _ int) string {
//	    return strconv.Itoa(n * 2)
//	})
//	groups := collections.GroupBy(c, func(n int) string {
//	    if n%2 == 0 { return "even" }
//	    return "odd"
//	})
//
// # Laravel equivalents
//
// The method names map 1-to-1 to Laravel's Collection methods where possible.
// Differences:
//   - Go callbacks receive (item, index) rather than (item, key).
//   - Operations requiring comparable keys accept a key-extraction fn
//     (e.g., Diff, Intersect, Unique) instead of relying on implicit equality.
//   - Type-transforming operations (Map, GroupBy, …) are package-level functions.
type Collection[T any] struct {
	items []T
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructors
// ─────────────────────────────────────────────────────────────────────────────

// New creates a Collection from a variadic list of items (copied).
func New[T any](items ...T) *Collection[T] {
	dst := make([]T, len(items))
	copy(dst, items)
	return &Collection[T]{items: dst}
}

// From creates a Collection from a slice (the slice is copied).
func From[T any](items []T) *Collection[T] {
	dst := make([]T, len(items))
	copy(dst, items)
	return &Collection[T]{items: dst}
}

// Empty creates an empty Collection of type T.
func Empty[T any]() *Collection[T] {
	return &Collection[T]{items: []T{}}
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessors
// ─────────────────────────────────────────────────────────────────────────────

// All returns a copy of the underlying slice.
func (c *Collection[T]) All() []T {
	out := make([]T, len(c.items))
	copy(out, c.items)
	return out
}

// ToSlice is an alias for [Collection.All].
func (c *Collection[T]) ToSlice() []T { return c.All() }

// ToJSON serialises the collection items to a JSON array.
func (c *Collection[T]) ToJSON() ([]byte, error) {
	return json.Marshal(c.items)
}

// Count returns the number of items in the collection.
func (c *Collection[T]) Count() int { return len(c.items) }

// IsEmpty reports whether the collection contains no items.
func (c *Collection[T]) IsEmpty() bool { return len(c.items) == 0 }

// IsNotEmpty reports whether the collection has at least one item.
func (c *Collection[T]) IsNotEmpty() bool { return len(c.items) > 0 }

// Get returns the item at index together with a presence flag.
// Returns the zero value and false when index is out of range.
func (c *Collection[T]) Get(index int) (T, bool) {
	var zero T
	if index < 0 || index >= len(c.items) {
		return zero, false
	}
	return c.items[index], true
}

// Has reports whether index is a valid position in the collection.
func (c *Collection[T]) Has(index int) bool {
	return index >= 0 && index < len(c.items)
}

// Keys returns the integer indices of the collection (0 … Count()-1).
func (c *Collection[T]) Keys() []int {
	keys := make([]int, len(c.items))
	for i := range keys {
		keys[i] = i
	}
	return keys
}

// Values returns a clean copy of the collection.
// Useful after [Collection.Forget] / [Collection.Pull] to reset logical ordering.
func (c *Collection[T]) Values() *Collection[T] { return From(c.items) }

// String returns a JSON representation of the collection.
// It implements [fmt.Stringer].
func (c *Collection[T]) String() string {
	b, err := c.ToJSON()
	if err != nil {
		return fmt.Sprintf("%v", c.items)
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Iteration
// ─────────────────────────────────────────────────────────────────────────────

// Each calls fn(item, index) for every item.
// Returns c unchanged so it can be used in chains.
func (c *Collection[T]) Each(fn func(T, int)) {
	for i, item := range c.items {
		fn(item, i)
	}
}

// Tap calls fn(c) for side-effects (e.g. logging or debugging) and returns
// c unchanged for further chaining.
func (c *Collection[T]) Tap(fn func(*Collection[T])) *Collection[T] {
	fn(c)
	return c
}

// Dump prints the collection to stdout and returns c for chaining.
func (c *Collection[T]) Dump() *Collection[T] {
	fmt.Println(c.String())
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
// Search & Lookup
// ─────────────────────────────────────────────────────────────────────────────

// First returns the first item, optionally matching fns[0].
// Returns the zero value and false when the collection is empty or no item
// satisfies the predicate.
func (c *Collection[T]) First(fns ...func(T) bool) (T, bool) {
	var zero T
	if len(fns) > 0 {
		for _, item := range c.items {
			if fns[0](item) {
				return item, true
			}
		}
		return zero, false
	}
	if len(c.items) == 0 {
		return zero, false
	}
	return c.items[0], true
}

// FirstOrFail returns the first item matching fn, or [ErrNoMatchingItems].
func (c *Collection[T]) FirstOrFail(fn func(T) bool) (T, error) {
	item, ok := c.First(fn)
	if !ok {
		return item, ErrNoMatchingItems
	}
	return item, nil
}

// Last returns the last item, optionally matching fns[0].
// Returns the zero value and false when the collection is empty or no item
// satisfies the predicate.
func (c *Collection[T]) Last(fns ...func(T) bool) (T, bool) {
	var zero T
	if len(fns) > 0 {
		var found T
		matched := false
		for _, item := range c.items {
			if fns[0](item) {
				found = item
				matched = true
			}
		}
		return found, matched
	}
	if len(c.items) == 0 {
		return zero, false
	}
	return c.items[len(c.items)-1], true
}

// LastOrFail returns the last item matching fn, or [ErrNoMatchingItems].
func (c *Collection[T]) LastOrFail(fn func(T) bool) (T, error) {
	item, ok := c.Last(fn)
	if !ok {
		return item, ErrNoMatchingItems
	}
	return item, nil
}

// Contains reports whether at least one item satisfies fn.
func (c *Collection[T]) Contains(fn func(T) bool) bool {
	for _, item := range c.items {
		if fn(item) {
			return true
		}
	}
	return false
}

// Search returns the index of the first item for which fn returns true, or -1.
func (c *Collection[T]) Search(fn func(T) bool) int {
	for i, item := range c.items {
		if fn(item) {
			return i
		}
	}
	return -1
}

// ─────────────────────────────────────────────────────────────────────────────
// Transformation (type-preserving)
// ─────────────────────────────────────────────────────────────────────────────

// Filter returns a new collection with only the items for which fn(item, index)
// returns true.
func (c *Collection[T]) Filter(fn func(T, int) bool) *Collection[T] {
	out := make([]T, 0, len(c.items))
	for i, item := range c.items {
		if fn(item, i) {
			out = append(out, item)
		}
	}
	return &Collection[T]{items: out}
}

// Reject returns a new collection with items for which fn returns true removed.
// It is the complement of [Collection.Filter].
func (c *Collection[T]) Reject(fn func(T, int) bool) *Collection[T] {
	return c.Filter(func(item T, i int) bool { return !fn(item, i) })
}

// Where is an alias for [Collection.Filter].
func (c *Collection[T]) Where(fn func(T, int) bool) *Collection[T] {
	return c.Filter(fn)
}

// WhereNot is an alias for [Collection.Reject].
func (c *Collection[T]) WhereNot(fn func(T, int) bool) *Collection[T] {
	return c.Reject(fn)
}

// Map returns a new Collection[any] with each item transformed by fn(item, index).
//
// For type-safe transformation to a concrete type U, use the package-level
// [Map] function instead.
func (c *Collection[T]) Map(fn func(T, int) any) *Collection[any] {
	out := make([]any, len(c.items))
	for i, item := range c.items {
		out[i] = fn(item, i)
	}
	return &Collection[any]{items: out}
}

// FlatMap maps each item to a []any via fn and flattens the results one level.
//
// For type-safe flat-mapping, use the package-level [FlatMap] function.
func (c *Collection[T]) FlatMap(fn func(T, int) []any) *Collection[any] {
	out := make([]any, 0, len(c.items))
	for i, item := range c.items {
		out = append(out, fn(item, i)...)
	}
	return &Collection[any]{items: out}
}

// Pluck extracts a value from each item using fn and returns a Collection[any].
//
// For type-safe plucking, use the package-level [Pluck] function.
func (c *Collection[T]) Pluck(fn func(T) any) *Collection[any] {
	return c.Map(func(item T, _ int) any { return fn(item) })
}

// Reduce reduces the collection to a single value of the same type T.
//
// For reductions that change the type (T → U where T ≠ U), use the
// package-level [Reduce] function.
func (c *Collection[T]) Reduce(fn func(carry, item T) T, initial T) T {
	result := initial
	for _, item := range c.items {
		result = fn(result, item)
	}
	return result
}

// Unique returns a new collection with duplicates removed.
// fn extracts the comparison key; pass nil to use fmt.Sprintf("%v") for any T.
func (c *Collection[T]) Unique(fn func(T) any) *Collection[T] {
	if fn == nil {
		fn = func(item T) any { return fmt.Sprintf("%v", item) }
	}
	seen := make(map[any]struct{}, len(c.items))
	return c.Filter(func(item T, _ int) bool {
		k := fn(item)
		if _, ok := seen[k]; ok {
			return false
		}
		seen[k] = struct{}{}
		return true
	})
}

// Diff returns items in c that are not present in other.
// fn extracts the key used for equality comparison.
func (c *Collection[T]) Diff(other *Collection[T], fn func(T) any) *Collection[T] {
	set := make(map[any]struct{}, other.Count())
	other.Each(func(item T, _ int) { set[fn(item)] = struct{}{} })
	return c.Filter(func(item T, _ int) bool {
		_, found := set[fn(item)]
		return !found
	})
}

// Intersect returns items that appear in both c and other.
// fn extracts the key used for equality comparison.
func (c *Collection[T]) Intersect(other *Collection[T], fn func(T) any) *Collection[T] {
	set := make(map[any]struct{}, other.Count())
	other.Each(func(item T, _ int) { set[fn(item)] = struct{}{} })
	return c.Filter(func(item T, _ int) bool {
		_, found := set[fn(item)]
		return found
	})
}

// Reverse returns a new collection with items in reversed order.
func (c *Collection[T]) Reverse() *Collection[T] {
	n := len(c.items)
	out := make([]T, n)
	for i, item := range c.items {
		out[n-1-i] = item
	}
	return &Collection[T]{items: out}
}

// Sort returns a new collection sorted by the given less function.
// The sort is stable: equal elements preserve their original order.
func (c *Collection[T]) Sort(less func(a, b T) bool) *Collection[T] {
	out := make([]T, len(c.items))
	copy(out, c.items)
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return &Collection[T]{items: out}
}

// SortBy returns a new collection sorted in ascending order by the float64
// value extracted by fn.
func (c *Collection[T]) SortBy(fn func(T) float64) *Collection[T] {
	return c.Sort(func(a, b T) bool { return fn(a) < fn(b) })
}

// SortByDesc returns a new collection sorted in descending order by fn.
func (c *Collection[T]) SortByDesc(fn func(T) float64) *Collection[T] {
	return c.Sort(func(a, b T) bool { return fn(a) > fn(b) })
}

// Shuffle returns a new collection with items in a randomly shuffled order.
func (c *Collection[T]) Shuffle() *Collection[T] {
	out := make([]T, len(c.items))
	copy(out, c.items)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return &Collection[T]{items: out}
}

// Random returns a new collection with n randomly selected items (without
// replacement). If n >= Count(), a shuffled copy of the full collection is
// returned.
func (c *Collection[T]) Random(n int) *Collection[T] {
	s := c.Shuffle()
	if n >= s.Count() {
		return s
	}
	return s.Take(n)
}

// ─────────────────────────────────────────────────────────────────────────────
// Add / Remove
// ─────────────────────────────────────────────────────────────────────────────

// Push returns a new collection with items appended.
func (c *Collection[T]) Push(items ...T) *Collection[T] {
	out := make([]T, len(c.items)+len(items))
	copy(out, c.items)
	copy(out[len(c.items):], items)
	return &Collection[T]{items: out}
}

// Append is an alias for [Collection.Push].
func (c *Collection[T]) Append(items ...T) *Collection[T] { return c.Push(items...) }

// Prepend returns a new collection with items inserted at the front.
func (c *Collection[T]) Prepend(items ...T) *Collection[T] {
	out := make([]T, len(items)+len(c.items))
	copy(out, items)
	copy(out[len(items):], c.items)
	return &Collection[T]{items: out}
}

// Pop removes and returns the last item together with the remaining collection.
// Returns the zero value, c, and false if the collection is empty.
func (c *Collection[T]) Pop() (T, *Collection[T], bool) {
	var zero T
	if len(c.items) == 0 {
		return zero, c, false
	}
	return c.items[len(c.items)-1], From(c.items[:len(c.items)-1]), true
}

// Shift removes and returns the first item together with the remaining
// collection. Returns the zero value, c, and false if the collection is empty.
func (c *Collection[T]) Shift() (T, *Collection[T], bool) {
	var zero T
	if len(c.items) == 0 {
		return zero, c, false
	}
	return c.items[0], From(c.items[1:]), true
}

// Pull removes and returns the item at index together with the remaining
// collection. Returns the zero value, c, and false if index is out of range.
func (c *Collection[T]) Pull(index int) (T, *Collection[T], bool) {
	var zero T
	if index < 0 || index >= len(c.items) {
		return zero, c, false
	}
	item := c.items[index]
	out := make([]T, 0, len(c.items)-1)
	out = append(out, c.items[:index]...)
	out = append(out, c.items[index+1:]...)
	return item, &Collection[T]{items: out}, true
}

// Forget returns a new collection with the item at index removed.
// Returns c unchanged if index is out of range.
func (c *Collection[T]) Forget(index int) *Collection[T] {
	_, col, _ := c.Pull(index)
	return col
}

// Concat returns a new collection with all items from other appended.
func (c *Collection[T]) Concat(other *Collection[T]) *Collection[T] {
	return c.Push(other.items...)
}

// Merge is an alias for [Collection.Concat].
func (c *Collection[T]) Merge(other *Collection[T]) *Collection[T] { return c.Concat(other) }

// ─────────────────────────────────────────────────────────────────────────────
// Slicing & Pagination
// ─────────────────────────────────────────────────────────────────────────────

// Take returns at most n items from the start.
// A negative n returns items from the end (e.g. Take(-3) ≡ last 3 items).
func (c *Collection[T]) Take(n int) *Collection[T] {
	total := len(c.items)
	if n < 0 {
		start := total + n
		if start < 0 {
			start = 0
		}
		return From(c.items[start:])
	}
	if n > total {
		n = total
	}
	return From(c.items[:n])
}

// TakeUntil returns items from the start until fn returns true (exclusive).
func (c *Collection[T]) TakeUntil(fn func(T) bool) *Collection[T] {
	out := make([]T, 0)
	for _, item := range c.items {
		if fn(item) {
			break
		}
		out = append(out, item)
	}
	return &Collection[T]{items: out}
}

// TakeWhile returns items from the start while fn returns true.
func (c *Collection[T]) TakeWhile(fn func(T) bool) *Collection[T] {
	return c.TakeUntil(func(item T) bool { return !fn(item) })
}

// Skip returns a new collection skipping the first n items.
// A negative n skips items counted from the end.
func (c *Collection[T]) Skip(n int) *Collection[T] {
	total := len(c.items)
	if n < 0 {
		end := total + n
		if end < 0 {
			return Empty[T]()
		}
		return From(c.items[:end])
	}
	if n >= total {
		return Empty[T]()
	}
	return From(c.items[n:])
}

// SkipUntil skips items until fn returns true, then returns the rest.
func (c *Collection[T]) SkipUntil(fn func(T) bool) *Collection[T] {
	for i, item := range c.items {
		if fn(item) {
			return From(c.items[i:])
		}
	}
	return Empty[T]()
}

// SkipWhile skips items while fn returns true, then returns the rest.
func (c *Collection[T]) SkipWhile(fn func(T) bool) *Collection[T] {
	return c.SkipUntil(func(item T) bool { return !fn(item) })
}

// Slice returns items starting at offset with at most length items.
// A negative offset counts from the end. length of -1 means "to the end".
func (c *Collection[T]) Slice(offset, length int) *Collection[T] {
	total := len(c.items)
	if offset < 0 {
		offset = total + offset
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return Empty[T]()
	}
	if length < 0 {
		return From(c.items[offset:])
	}
	end := offset + length
	if end > total {
		end = total
	}
	return From(c.items[offset:end])
}

// Chunk splits the collection into consecutive groups of size, returning a
// plain [][]T. The last group may contain fewer than size items.
// Returns an empty [][]T if size <= 0 or the collection is empty.
//
// To work with each chunk as a *Collection, wrap with [From]:
//
//	for _, chunk := range c.Chunk(2) {
//	    sub := collections.From(chunk)
//	    // ...
//	}
func (c *Collection[T]) Chunk(size int) [][]T {
	if size <= 0 || len(c.items) == 0 {
		return [][]T{}
	}
	chunks := make([][]T, 0, (len(c.items)+size-1)/size)
	for i := 0; i < len(c.items); i += size {
		end := i + size
		if end > len(c.items) {
			end = len(c.items)
		}
		chunk := make([]T, end-i)
		copy(chunk, c.items[i:end])
		chunks = append(chunks, chunk)
	}
	return chunks
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregation
// ─────────────────────────────────────────────────────────────────────────────

// Sum returns the sum of all items using fn to extract numeric values.
func (c *Collection[T]) Sum(fn func(T) float64) float64 {
	var sum float64
	for _, item := range c.items {
		sum += fn(item)
	}
	return sum
}

// Average returns the arithmetic mean of all items, or 0 for an empty
// collection.
func (c *Collection[T]) Average(fn func(T) float64) float64 {
	if len(c.items) == 0 {
		return 0
	}
	return c.Sum(fn) / float64(len(c.items))
}

// Min returns the item with the smallest value extracted by fn.
// Returns the zero value and false if the collection is empty.
func (c *Collection[T]) Min(fn func(T) float64) (T, bool) {
	var zero T
	if len(c.items) == 0 {
		return zero, false
	}
	minItem, minVal := c.items[0], fn(c.items[0])
	for _, item := range c.items[1:] {
		if v := fn(item); v < minVal {
			minVal, minItem = v, item
		}
	}
	return minItem, true
}

// Max returns the item with the largest value extracted by fn.
// Returns the zero value and false if the collection is empty.
func (c *Collection[T]) Max(fn func(T) float64) (T, bool) {
	var zero T
	if len(c.items) == 0 {
		return zero, false
	}
	maxItem, maxVal := c.items[0], fn(c.items[0])
	for _, item := range c.items[1:] {
		if v := fn(item); v > maxVal {
			maxVal, maxItem = v, item
		}
	}
	return maxItem, true
}

// ─────────────────────────────────────────────────────────────────────────────
// Grouping / Partitioning
// ─────────────────────────────────────────────────────────────────────────────

// GroupBy groups items by the key returned by fn.
// Returns map[any]*Collection[T]. For typed keys use the package-level [GroupBy].
func (c *Collection[T]) GroupBy(fn func(T) any) map[any]*Collection[T] {
	groups := make(map[any]*Collection[T])
	for _, item := range c.items {
		k := fn(item)
		if groups[k] == nil {
			groups[k] = Empty[T]()
		}
		groups[k].items = append(groups[k].items, item)
	}
	return groups
}

// KeyBy returns a map keyed by the value extracted by fn.
// Returns map[any]T. For typed keys use the package-level [KeyBy].
func (c *Collection[T]) KeyBy(fn func(T) any) map[any]T {
	out := make(map[any]T, len(c.items))
	for _, item := range c.items {
		out[fn(item)] = item
	}
	return out
}

// Partition splits the collection into two:
// the first contains items for which fn returns true; the second the rest.
func (c *Collection[T]) Partition(fn func(T) bool) (*Collection[T], *Collection[T]) {
	pass := make([]T, 0)
	fail := make([]T, 0)
	for _, item := range c.items {
		if fn(item) {
			pass = append(pass, item)
		} else {
			fail = append(fail, item)
		}
	}
	return &Collection[T]{items: pass}, &Collection[T]{items: fail}
}

// ─────────────────────────────────────────────────────────────────────────────
// String helpers
// ─────────────────────────────────────────────────────────────────────────────

// Implode joins all items into a string using sep, converting each item with fn.
func (c *Collection[T]) Implode(sep string, fn func(T) string) string {
	parts := make([]string, len(c.items))
	for i, item := range c.items {
		parts[i] = fn(item)
	}
	return strings.Join(parts, sep)
}

// Flip returns a map from each item's string representation to its index.
func (c *Collection[T]) Flip() map[string]int {
	out := make(map[string]int, len(c.items))
	for i, item := range c.items {
		out[fmt.Sprintf("%v", item)] = i
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Conditional pipeline
// ─────────────────────────────────────────────────────────────────────────────

// When calls fn(c) if condition is true and returns the result.
// Otherwise returns c unchanged.
func (c *Collection[T]) When(condition bool, fn func(*Collection[T]) *Collection[T]) *Collection[T] {
	if condition {
		return fn(c)
	}
	return c
}

// Unless calls fn(c) if condition is false; otherwise returns c.
func (c *Collection[T]) Unless(condition bool, fn func(*Collection[T]) *Collection[T]) *Collection[T] {
	return c.When(!condition, fn)
}

// WhenEmpty calls fn(c) if c is empty; otherwise returns c.
func (c *Collection[T]) WhenEmpty(fn func(*Collection[T]) *Collection[T]) *Collection[T] {
	return c.When(c.IsEmpty(), fn)
}

// WhenNotEmpty calls fn(c) if c is not empty; otherwise returns c.
func (c *Collection[T]) WhenNotEmpty(fn func(*Collection[T]) *Collection[T]) *Collection[T] {
	return c.When(c.IsNotEmpty(), fn)
}
