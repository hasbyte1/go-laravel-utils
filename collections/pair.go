package collections

import "fmt"

// Pair holds two values of possibly different types.
// It is the element type produced by [Zip].
//
// Portability note: in Python this maps to a 2-tuple; in TypeScript to
// [A, B]; in Rust to (A, B).
type Pair[A, B any] struct {
	First  A
	Second B
}

// String returns a human-readable representation: "(first, second)".
func (p Pair[A, B]) String() string {
	return fmt.Sprintf("(%v, %v)", p.First, p.Second)
}
