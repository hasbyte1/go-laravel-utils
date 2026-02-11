// Package collections provides a generic, fluent Collection type and
// standalone helper functions for common slice operations, inspired by
// Laravel's Illuminate/Collections.
//
// # Overview
//
// The central type is [Collection][T], a generic wrapper around a slice of T
// that exposes a rich, chainable API:
//
//	result := collections.New(1, 2, 3, 4, 5, 6, 7, 8, 9, 10).
//	    Filter(func(n, _ int) bool { return n%2 == 0 }).
//	    SortByDesc(func(n int) float64 { return float64(n) }).
//	    Take(3).
//	    Implode(", ", strconv.Itoa) // → "10, 8, 6"
//
// # Immutability
//
// All transformation methods return a *new* Collection, leaving the original
// unchanged. This makes Collection values safe to pass across goroutines
// without locking and avoids accidental aliasing bugs in pipelines.
//
// # Type-transforming operations
//
// Go generics do not allow methods to introduce new type parameters, so
// operations that change the element type are exposed as package-level
// functions:
//
//	// Method-based (returns Collection[any]):
//	c.Map(func(n int, _ int) any { return n * 2 })
//
//	// Package-level (returns Collection[string], fully typed):
//	collections.Map(c, func(n int, _ int) string { return strconv.Itoa(n) })
//
// Package-level functions: [Map], [FlatMap], [Reduce], [Pluck], [GroupBy],
// [KeyBy], [Zip], [Combine], [Collapse], [Flatten], [FlattenDeep].
//
// # Macros (runtime extension)
//
// Register named functions at runtime via [RegisterMacro] and call them
// through [Collection.Macro]:
//
//	collections.RegisterMacro("evens", func(col any, _ ...any) any {
//	    c := col.(*collections.Collection[int])
//	    return c.Filter(func(n, _ int) bool { return n%2 == 0 })
//	})
//
//	evens, _ := collections.New(1, 2, 3, 4).Macro("evens")
//
// # Portability
//
// The Collection API mirrors standard functional-programming patterns
// (map/filter/reduce) that translate directly to other languages:
//
//   - JavaScript: Array.prototype.map/filter/reduce + custom class
//   - Python: list comprehensions, itertools, or a custom Collection class
//   - Rust: Iterator adapter chains
//
// See the repository README for migration skeletons in Node.js and Python.
package collections
