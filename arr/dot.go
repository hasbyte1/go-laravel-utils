package arr

import "strings"

// ─────────────────────────────────────────────────────────────────────────────
// Dot-notation helpers for map[string]any
//
// These functions allow reading, writing, and testing values in deeply nested
// map[string]any structures using dot-separated key paths, mirroring
// Laravel's Arr::dot, Arr::get, Arr::set, Arr::has, Arr::forget, etc.
//
// Example map:
//
//	m := map[string]any{
//	    "user": map[string]any{
//	        "name": "Alice",
//	        "address": map[string]any{"city": "London"},
//	    },
//	}
//
//	Get(m, "user.address.city")  → "London"
//	Set(m, "user.age", 30)
//	Has(m, "user.name")          → true
//	Forget(m, "user.address")
// ─────────────────────────────────────────────────────────────────────────────

// Dot flattens a nested map[string]any into a single-level map using dot
// notation for the keys.
//
//	Dot(map[string]any{"a": map[string]any{"b": 1}})
//	// → map[string]any{"a.b": 1}
func Dot(m map[string]any) map[string]any {
	out := make(map[string]any)
	dotFlatten("", m, out)
	return out
}

func dotFlatten(prefix string, m map[string]any, out map[string]any) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if nested, ok := v.(map[string]any); ok {
			dotFlatten(key, nested, out)
		} else {
			out[key] = v
		}
	}
}

// Undot expands a flat dot-notation map into a nested map[string]any.
//
//	Undot(map[string]any{"a.b": 1, "a.c": 2})
//	// → map[string]any{"a": map[string]any{"b": 1, "c": 2}}
func Undot(m map[string]any) map[string]any {
	out := make(map[string]any)
	for key, val := range m {
		Set(out, key, val)
	}
	return out
}

// Get retrieves a value from m using a dot-notation key.
// Returns def[0] (or nil) when the key does not exist.
//
//	Get(m, "user.address.city")        // "London"
//	Get(m, "user.missing", "default")  // "default"
func Get(m map[string]any, key string, def ...any) any {
	segments := strings.Split(key, ".")
	current := m
	for i, seg := range segments {
		val, ok := current[seg]
		if !ok {
			if len(def) > 0 {
				return def[0]
			}
			return nil
		}
		if i == len(segments)-1 {
			return val
		}
		nested, ok := val.(map[string]any)
		if !ok {
			if len(def) > 0 {
				return def[0]
			}
			return nil
		}
		current = nested
	}
	return nil
}

// Set writes value into m at the dot-notation key, creating intermediate
// maps as needed.
//
//	Set(m, "user.address.postcode", "EC1")
func Set(m map[string]any, key string, value any) {
	segments := strings.SplitN(key, ".", 2)
	if len(segments) == 1 {
		m[key] = value
		return
	}
	seg, rest := segments[0], segments[1]
	nested, ok := m[seg].(map[string]any)
	if !ok {
		nested = make(map[string]any)
		m[seg] = nested
	}
	Set(nested, rest, value)
}

// Has reports whether the dot-notation key exists in m.
func Has(m map[string]any, key string) bool {
	return hasKey(m, strings.Split(key, "."))
}

func hasKey(m map[string]any, segments []string) bool {
	if len(segments) == 0 {
		return false
	}
	val, ok := m[segments[0]]
	if !ok {
		return false
	}
	if len(segments) == 1 {
		return true
	}
	nested, ok := val.(map[string]any)
	if !ok {
		return false
	}
	return hasKey(nested, segments[1:])
}

// HasAll reports whether all dot-notation keys exist in m.
func HasAll(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if !Has(m, key) {
			return false
		}
	}
	return true
}

// HasAny reports whether any of the dot-notation keys exist in m.
func HasAny(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if Has(m, key) {
			return true
		}
	}
	return false
}

// Forget removes the dot-notation key from m.
// Intermediate maps are not cleaned up.
func Forget(m map[string]any, key string) {
	segments := strings.SplitN(key, ".", 2)
	if len(segments) == 1 {
		delete(m, key)
		return
	}
	seg, rest := segments[0], segments[1]
	nested, ok := m[seg].(map[string]any)
	if !ok {
		return
	}
	Forget(nested, rest)
}

// Only returns a new map containing only the specified top-level keys.
// Dot-notation keys in the keep list are not supported; use [Get] and
// [Set] for fine-grained filtering.
func Only(m map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// Except returns a shallow copy of m without the specified top-level keys.
func Except(m map[string]any, keys ...string) map[string]any {
	drop := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		drop[k] = struct{}{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if _, skip := drop[k]; !skip {
			out[k] = v
		}
	}
	return out
}

// Merge merges src into dst, returning dst.
// Values in src overwrite values in dst for matching keys.
// Nested maps are merged recursively.
func Merge(dst, src map[string]any) map[string]any {
	for k, srcVal := range src {
		dstVal, ok := dst[k]
		if ok {
			dstMap, dstIsMap := dstVal.(map[string]any)
			srcMap, srcIsMap := srcVal.(map[string]any)
			if dstIsMap && srcIsMap {
				Merge(dstMap, srcMap)
				continue
			}
		}
		dst[k] = srcVal
	}
	return dst
}
