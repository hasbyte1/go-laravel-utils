// Package arr provides standalone, framework-agnostic helper functions for
// Go slices and dot-notation map access, inspired by Laravel's Arr facade and
// PHP's array_* functions.
//
// # Slice helpers
//
// All slice helpers are generic (Go 1.18+) and operate on plain []T values —
// no wrapper type required:
//
//	evens  := arr.Filter([]int{1, 2, 3, 4, 5}, func(n, _ int) bool { return n%2 == 0 })
//	names  := arr.Pluck(users, func(u User) string { return u.Name })
//	chunks := arr.Chunk([]int{1, 2, 3, 4, 5}, 2) // → [[1 2] [3 4] [5]]
//
// # Dot-notation map access
//
// Functions in this package also support reading and writing values in
// nested map[string]any structures using dot notation:
//
//	m := map[string]any{
//	    "user": map[string]any{
//	        "name": "Alice",
//	        "address": map[string]any{"city": "London"},
//	    },
//	}
//	arr.Get(m, "user.address.city")          // → "London"
//	arr.Set(m, "user.address.postcode", "EC1")
//	arr.Has(m, "user.name")                  // → true
//	arr.Forget(m, "user.address")
//	flat := arr.Dot(m)                       // → {"user.name": "Alice"}
//
// # Portability
//
// All helpers follow the map/filter/reduce pattern and translate directly to
// other languages without Go-specific idioms. See the repository README for
// Node.js and Python equivalents.
package arr
