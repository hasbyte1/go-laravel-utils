package collections

import (
	"fmt"
	"sync"
)

// MacroFunc is the function signature for a registered macro.
//
// The collection is passed as an any (interface{}) so that macros can be
// registered once and used across any Collection[T] instantiation.
// Type-assert inside the macro to the concrete *Collection[YourType].
type MacroFunc func(collection any, args ...any) any

// macroRegistry is the package-level, goroutine-safe macro store.
var macroRegistry struct {
	mu     sync.RWMutex
	macros map[string]MacroFunc
}

func init() {
	macroRegistry.macros = make(map[string]MacroFunc)
}

// RegisterMacro adds a named macro to the global registry.
// If a macro with that name already exists it is replaced.
// Safe to call from multiple goroutines.
//
// Example – register a macro that keeps only even integers:
//
//	collections.RegisterMacro("evens", func(col any, _ ...any) any {
//	    c := col.(*collections.Collection[int])
//	    return c.Filter(func(n int, _ int) bool { return n%2 == 0 })
//	})
//
//	c   := collections.New(1, 2, 3, 4, 5)
//	res, _ := c.Macro("evens")          // *Collection[int]{2, 4}
func RegisterMacro(name string, fn MacroFunc) {
	macroRegistry.mu.Lock()
	defer macroRegistry.mu.Unlock()
	macroRegistry.macros[name] = fn
}

// HasMacro reports whether a macro with the given name is registered.
func HasMacro(name string) bool {
	macroRegistry.mu.RLock()
	defer macroRegistry.mu.RUnlock()
	_, ok := macroRegistry.macros[name]
	return ok
}

// FlushMacros removes all registered macros.
// Intended for use in tests.
func FlushMacros() {
	macroRegistry.mu.Lock()
	defer macroRegistry.mu.Unlock()
	macroRegistry.macros = make(map[string]MacroFunc)
}

// CallMacro calls the named macro with the supplied collection and args.
// Returns (nil, ErrMacroNotFound) if no macro is registered under name.
func CallMacro(name string, collection any, args ...any) (any, error) {
	macroRegistry.mu.RLock()
	fn, ok := macroRegistry.macros[name]
	macroRegistry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrMacroNotFound, name)
	}
	return fn(collection, args...), nil
}

// Macro calls the named registered macro on c, forwarding args.
// This is a convenience wrapper around the package-level [CallMacro].
func (c *Collection[T]) Macro(name string, args ...any) (any, error) {
	return CallMacro(name, c, args...)
}
