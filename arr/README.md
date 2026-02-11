# arr

Package `arr` provides generic slice helpers and dot-notation access for
`map[string]any` structures, modelled after Laravel's `Arr` facade.

```
go get github.com/hasbyte1/go-laravel-utils/arr
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [Slice helpers](#slice-helpers)
   - [Searching & testing](#searching--testing)
   - [Transformation](#transformation)
   - [Set operations](#set-operations)
   - [Restructuring](#restructuring)
   - [Sorting & randomisation](#sorting--randomisation)
   - [Aggregation](#aggregation)
3. [Dot-notation map helpers](#dot-notation-map-helpers)
4. [Edge cases](#edge-cases)
5. [Porting guide](#porting-guide)
   - [Node.js / TypeScript](#nodejs--typescript)
   - [Python](#python)
6. [Laravel comparison](#laravel-comparison)

---

## Quick start

```go
import "github.com/hasbyte1/go-laravel-utils/arr"

// Slice helpers
evens := arr.Filter([]int{1, 2, 3, 4}, func(n, _ int) bool { return n%2 == 0 })
// [2 4]

doubled := arr.Map([]int{1, 2, 3}, func(n, _ int) int { return n * 2 })
// [2 4 6]

groups := arr.GroupBy([]int{1, 2, 3, 4}, func(n int) string {
    if n%2 == 0 { return "even" }
    return "odd"
})
// groups["even"] → [2 4]

// Dot-notation map access
m := map[string]any{
    "db": map[string]any{"host": "localhost", "port": 5432},
}
arr.Get(m, "db.host")        // "localhost"
arr.Set(m, "db.name", "app")
arr.Has(m, "db.port")        // true
arr.Forget(m, "db.port")
```

---

## Slice helpers

All slice helpers return new slices and never modify their inputs.

### Searching & testing

#### `First`

```go
func First[T any](items []T, fns ...func(T) bool) (T, bool)
```

Returns the first element, or the first element matching an optional predicate.
Returns the zero value and `false` when the slice is empty or no match is found.

```go
v, ok := arr.First([]int{10, 20, 30})               // 10, true
v, ok  = arr.First([]int{1, 2, 3}, func(n int) bool { return n > 1 }) // 2, true
_, ok  = arr.First([]int{})                          // 0, false
```

#### `Last`

```go
func Last[T any](items []T, fns ...func(T) bool) (T, bool)
```

Same as `First` but returns the last matching element.

```go
v, ok := arr.Last([]int{10, 20, 30})                  // 30, true
v, ok  = arr.Last([]int{1, 2, 3, 4}, func(n int) bool { return n < 3 }) // 2, true
```

#### `Contains`

```go
func Contains[T any](items []T, fn func(T) bool) bool
```

Reports whether at least one element satisfies `fn`.

```go
arr.Contains([]int{1, 2, 3}, func(n int) bool { return n == 2 }) // true
```

#### `ContainsValue`

```go
func ContainsValue[T comparable](items []T, value T) bool
```

Reports whether `value` appears in `items` (requires comparable `T`).

```go
arr.ContainsValue([]string{"a", "b", "c"}, "b") // true
```

#### `IndexOf`

```go
func IndexOf[T comparable](items []T, value T) int
```

Returns the index of the first occurrence of `value`, or `-1`.

```go
arr.IndexOf([]int{10, 20, 30}, 20) // 1
arr.IndexOf([]int{10, 20}, 99)     // -1
```

#### `Search`

```go
func Search[T any](items []T, fn func(T) bool) int
```

Returns the index of the first element satisfying `fn`, or `-1`.

```go
arr.Search([]int{1, 2, 3}, func(n int) bool { return n == 3 }) // 2
```

---

### Transformation

#### `Map`

```go
func Map[T, U any](items []T, fn func(T, int) U) []U
```

Applies `fn(item, index)` to each element.

```go
arr.Map([]int{1, 2, 3}, func(n, _ int) int { return n * 2 }) // [2 4 6]
```

#### `Filter`

```go
func Filter[T any](items []T, fn func(T, int) bool) []T
```

Returns elements for which `fn` returns `true`.

```go
arr.Filter([]int{1, 2, 3, 4, 5}, func(n, _ int) bool { return n%2 == 0 }) // [2 4]
```

#### `Reject`

```go
func Reject[T any](items []T, fn func(T, int) bool) []T
```

Inverse of `Filter` — returns elements for which `fn` returns `false`.

```go
arr.Reject([]int{1, 2, 3, 4, 5}, func(n, _ int) bool { return n%2 == 0 }) // [1 3 5]
```

#### `Reduce`

```go
func Reduce[T, U any](items []T, fn func(U, T, int) U, initial U) U
```

Left-folds `items` into a single value of a potentially different type.

```go
sum := arr.Reduce([]int{1, 2, 3}, func(acc, n, _ int) int { return acc + n }, 0) // 6
```

#### `FlatMap`

```go
func FlatMap[T, U any](items []T, fn func(T, int) []U) []U
```

Maps each element to a `[]U` and flattens the results.

```go
arr.FlatMap([]int{1, 2, 3}, func(n, _ int) []int { return []int{n, n * 10} })
// [1 10 2 20 3 30]
```

#### `Pluck`

```go
func Pluck[T, U any](items []T, fn func(T) U) []U
```

Extracts a single field from each struct element.

```go
type User struct { Name string }
arr.Pluck([]User{{"Alice"}, {"Bob"}}, func(u User) string { return u.Name })
// ["Alice" "Bob"]
```

---

### Set operations

#### `Unique`

```go
func Unique[T comparable](items []T) []T
```

Removes duplicates, preserving the first occurrence.

```go
arr.Unique([]int{1, 2, 2, 3, 3, 3}) // [1 2 3]
```

#### `UniqueBy`

```go
func UniqueBy[T any, K comparable](items []T, fn func(T) K) []T
```

Removes duplicates using a key function, keeping the first element per key.

```go
type Item struct{ ID, Val int }
arr.UniqueBy([]Item{{1, 10}, {2, 20}, {1, 99}}, func(i Item) int { return i.ID })
// [{1 10} {2 20}]
```

#### `Diff`

```go
func Diff[T comparable](a, b []T) []T
```

Returns elements in `a` that are not in `b`.

```go
arr.Diff([]int{1, 2, 3, 4, 5}, []int{2, 4}) // [1 3 5]
```

#### `Intersect`

```go
func Intersect[T comparable](a, b []T) []T
```

Returns elements that appear in both `a` and `b`.

```go
arr.Intersect([]int{1, 2, 3, 4}, []int{2, 4, 6}) // [2 4]
```

---

### Restructuring

#### `Chunk`

```go
func Chunk[T any](items []T, size int) [][]T
```

Splits a slice into consecutive groups of `size`. The last group may be smaller.
Returns an empty slice when `size ≤ 0` or `items` is empty.

```go
for _, chunk := range arr.Chunk([]int{1, 2, 3, 4, 5}, 2) {
    fmt.Println(chunk)
}
// [1 2]
// [3 4]
// [5]
```

#### `Collapse`

```go
func Collapse[T any](items [][]T) []T
```

Flattens a slice of slices into a single flat slice.

```go
arr.Collapse([][]int{{1, 2}, {3, 4}, {5}}) // [1 2 3 4 5]
```

#### `Flatten`

```go
func Flatten(items any) []any
```

Recursively flattens any nested `[]any` structure.

```go
arr.Flatten([]any{1, []any{2, 3}, []any{4, []any{5}}}) // [1 2 3 4 5]
```

#### `Reverse`

```go
func Reverse[T any](items []T) []T
```

Returns a reversed copy without modifying the original.

```go
arr.Reverse([]int{1, 2, 3}) // [3 2 1]
```

#### `Prepend`

```go
func Prepend[T any](items []T, values ...T) []T
```

Returns a new slice with `values` added at the front.

```go
arr.Prepend([]int{3, 4}, 1, 2) // [1 2 3 4]
```

#### `Wrap`

```go
func Wrap[T any](value T) []T
```

Wraps a single value in a slice.

```go
arr.Wrap(42) // [42]
```

#### `Partition`

```go
func Partition[T any](items []T, fn func(T) bool) ([]T, []T)
```

Splits items into two groups: those that satisfy `fn` and those that do not.

```go
evens, odds := arr.Partition([]int{1, 2, 3, 4, 5}, func(n int) bool { return n%2 == 0 })
// evens [2 4], odds [1 3 5]
```

#### `Zip`

```go
type Pair[A, B any] struct { First A; Second B }
func Zip[A, B any](a []A, b []B) []Pair[A, B]
```

Pairs elements from two slices at the same index. Stops at the shorter slice.

```go
pairs := arr.Zip([]string{"a", "b"}, []int{1, 2})
// [{a 1} {b 2}]
```

#### `Combine`

```go
func Combine[K comparable, V any](keys []K, values []V) (map[K]V, error)
```

Creates a map from equal-length key and value slices. Returns an error if lengths differ.

```go
m, err := arr.Combine([]string{"x", "y"}, []int{10, 20})
// m["y"] == 20
```

#### `GroupBy`

```go
func GroupBy[T any, K comparable](items []T, fn func(T) K) map[K][]T
```

Groups elements by the key returned by `fn`.

```go
groups := arr.GroupBy([]int{1, 2, 3, 4}, func(n int) string {
    if n%2 == 0 { return "even" }
    return "odd"
})
// groups["even"] = [2 4], groups["odd"] = [1 3]
```

#### `KeyBy`

```go
func KeyBy[T any, K comparable](items []T, fn func(T) K) map[K]T
```

Creates a map keyed by the value returned by `fn`. Last item wins on duplicate keys.

```go
type Item struct{ ID int }
keyed := arr.KeyBy([]Item{{1}, {2}, {3}}, func(i Item) int { return i.ID })
// keyed[2] = {2}
```

---

### Sorting & randomisation

#### `Sort`

```go
func Sort[T any](items []T, less func(a, b T) bool) []T
```

Returns a stably sorted copy of `items`.

```go
arr.Sort([]int{3, 1, 4, 1, 5}, func(a, b int) bool { return a < b })
// [1 1 3 4 5]
```

#### `Shuffle`

```go
func Shuffle[T any](items []T) []T
```

Returns a randomly shuffled copy without modifying the original.

```go
orig := []int{1, 2, 3, 4, 5}
shuffled := arr.Shuffle(orig) // orig is unchanged
```

#### `Random`

```go
func Random[T any](items []T, n int) []T
```

Returns `n` randomly selected items without replacement. Returns all items (shuffled)
when `n ≥ len(items)`.

```go
arr.Random([]int{1, 2, 3, 4, 5}, 3) // 3 random items
```

---

### Aggregation

#### `Sum`

```go
func Sum[T any](items []T, fn func(T) float64) float64
```

Sums the values returned by `fn` for each element.

```go
arr.Sum([]int{1, 2, 3, 4, 5}, func(n int) float64 { return float64(n) }) // 15
```

#### `Min`

```go
func Min[T any](items []T, fn func(T) float64) (T, bool)
```

Returns the element with the smallest value. Returns the zero value and `false` for
empty slices.

```go
v, ok := arr.Min([]int{3, 1, 4, 1, 5}, func(n int) float64 { return float64(n) })
// v = 1, ok = true
```

#### `Max`

```go
func Max[T any](items []T, fn func(T) float64) (T, bool)
```

Returns the element with the largest value.

```go
v, ok := arr.Max([]int{3, 1, 4, 1, 5}, func(n int) float64 { return float64(n) })
// v = 5, ok = true
```

---

## Dot-notation map helpers

These helpers allow navigating deeply nested `map[string]any` structures with
dot-separated key paths, mirroring Laravel's `Arr::dot`, `Arr::get`, `Arr::set`,
`Arr::has`, `Arr::forget`, etc.

Given:

```go
m := map[string]any{
    "user": map[string]any{
        "name":    "Alice",
        "address": map[string]any{"city": "London"},
    },
    "score": 42,
}
```

### `Dot`

```go
func Dot(m map[string]any) map[string]any
```

Flattens a nested map into a single-level map using dot-notation keys.

```go
flat := arr.Dot(m)
// flat["user.name"]         = "Alice"
// flat["user.address.city"] = "London"
// flat["score"]             = 42
```

### `Undot`

```go
func Undot(m map[string]any) map[string]any
```

Expands a flat dot-notation map back into a nested map.

```go
arr.Undot(map[string]any{"a.b": 1, "a.c": 2})
// {"a": {"b": 1, "c": 2}}
```

### `Get`

```go
func Get(m map[string]any, key string, def ...any) any
```

Retrieves the value at `key`. Returns `def[0]` (or `nil`) when the key does not exist.

```go
arr.Get(m, "user.address.city")         // "London"
arr.Get(m, "user.missing", "default")   // "default"
arr.Get(m, "user.missing")              // nil
```

### `Set`

```go
func Set(m map[string]any, key string, value any)
```

Writes `value` at `key`, creating intermediate maps as needed.

```go
arr.Set(m, "user.address.postcode", "EC1A")
arr.Get(m, "user.address.postcode") // "EC1A"
```

### `Has`

```go
func Has(m map[string]any, key string) bool
```

Reports whether the dot-notation key exists.

```go
arr.Has(m, "user.name")    // true
arr.Has(m, "user.missing") // false
```

### `HasAll`

```go
func HasAll(m map[string]any, keys ...string) bool
```

Reports whether **all** listed keys exist.

```go
arr.HasAll(m, "user.name", "score")     // true
arr.HasAll(m, "user.name", "missing")   // false
```

### `HasAny`

```go
func HasAny(m map[string]any, keys ...string) bool
```

Reports whether **any** listed key exists.

```go
arr.HasAny(m, "missing", "score") // true
arr.HasAny(m, "x", "y")          // false
```

### `Forget`

```go
func Forget(m map[string]any, key string)
```

Removes the value at `key`. Sibling keys are unaffected; intermediate maps are not
cleaned up.

```go
arr.Forget(m, "user.address.city")
arr.Has(m, "user.address.city")    // false
arr.Has(m, "user.address.country") // true (if it existed)
```

### `Only`

```go
func Only(m map[string]any, keys ...string) map[string]any
```

Returns a new map containing only the specified **top-level** keys.

```go
arr.Only(map[string]any{"a": 1, "b": 2, "c": 3}, "a", "c")
// {"a": 1, "c": 3}
```

### `Except`

```go
func Except(m map[string]any, keys ...string) map[string]any
```

Returns a shallow copy of `m` without the specified top-level keys.

```go
arr.Except(map[string]any{"a": 1, "b": 2, "c": 3}, "b")
// {"a": 1, "c": 3}
```

### `Merge`

```go
func Merge(dst, src map[string]any) map[string]any
```

Merges `src` into `dst`. Scalar values in `src` overwrite those in `dst`. Nested maps
are merged recursively. Returns `dst`.

```go
dst := map[string]any{"a": 1, "nested": map[string]any{"x": 10}}
src := map[string]any{"b": 2, "nested": map[string]any{"y": 20}}
arr.Merge(dst, src)
// dst = {"a": 1, "b": 2, "nested": {"x": 10, "y": 20}}
```

---

## Edge cases

| Situation | Behaviour |
|---|---|
| `First` / `Last` on empty slice | Returns zero value, `false` |
| `Min` / `Max` on empty slice | Returns zero value, `false` |
| `Chunk` with `size ≤ 0` | Returns `[][]T{}` |
| `Chunk` with empty input | Returns `[][]T{}` |
| `Combine` with mismatched lengths | Returns `nil, error` |
| `Zip` with unequal lengths | Stops at shorter slice |
| `Shuffle` / `Sort` | Never modifies the input slice |
| `Flatten` on non-slice `any` | Returns `[]any{value}` |
| `Get` missing key, no default | Returns `nil` |
| `Has` beyond a scalar node | Returns `false` |
| `Merge` scalar overwrite | `src` scalar replaces `dst` scalar |

---

## Porting guide

### Node.js / TypeScript

```typescript
// arr.ts — drop-in port of the arr slice helpers

export function first<T>(items: T[], fn?: (item: T) => boolean): T | undefined {
  if (fn) return items.find(fn);
  return items[0];
}

export function last<T>(items: T[], fn?: (item: T) => boolean): T | undefined {
  if (fn) {
    let found: T | undefined;
    for (const item of items) if (fn(item)) found = item;
    return found;
  }
  return items[items.length - 1];
}

export function chunk<T>(items: T[], size: number): T[][] {
  if (size <= 0) return [];
  const result: T[][] = [];
  for (let i = 0; i < items.length; i += size)
    result.push(items.slice(i, i + size));
  return result;
}

export function groupBy<T, K extends string | number | symbol>(
  items: T[],
  fn: (item: T) => K
): Record<K, T[]> {
  return items.reduce((acc, item) => {
    const key = fn(item);
    (acc[key] ??= []).push(item);
    return acc;
  }, {} as Record<K, T[]>);
}

export function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}

export function uniqueBy<T, K>(items: T[], fn: (item: T) => K): T[] {
  const seen = new Set<K>();
  return items.filter(item => {
    const k = fn(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function diff<T>(a: T[], b: T[]): T[] {
  const set = new Set(b);
  return a.filter(v => !set.has(v));
}

export function intersect<T>(a: T[], b: T[]): T[] {
  const set = new Set(b);
  return a.filter(v => set.has(v));
}

export function zip<A, B>(a: A[], b: B[]): Array<[A, B]> {
  const n = Math.min(a.length, b.length);
  return Array.from({ length: n }, (_, i) => [a[i], b[i]]);
}

export function combine<K extends string, V>(keys: K[], values: V[]): Record<K, V> {
  if (keys.length !== values.length) throw new Error("length mismatch");
  return Object.fromEntries(keys.map((k, i) => [k, values[i]])) as Record<K, V>;
}

// Dot-notation helpers
export function get(m: Record<string, unknown>, key: string, def?: unknown): unknown {
  const segments = key.split(".");
  let cur: unknown = m;
  for (const seg of segments) {
    if (typeof cur !== "object" || cur === null || !(seg in (cur as object)))
      return def ?? null;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

export function set(m: Record<string, unknown>, key: string, value: unknown): void {
  const [head, ...rest] = key.split(".");
  if (rest.length === 0) { m[head] = value; return; }
  if (typeof m[head] !== "object" || m[head] === null)
    m[head] = {} as Record<string, unknown>;
  set(m[head] as Record<string, unknown>, rest.join("."), value);
}

export function has(m: Record<string, unknown>, key: string): boolean {
  return get(m, key) !== null || key.split(".").reduce<unknown>((cur, seg) => {
    if (typeof cur !== "object" || cur === null) return undefined;
    return (cur as Record<string, unknown>)[seg];
  }, m) !== undefined;
}
```

### Python

```python
# arr.py — port of the arr package

from __future__ import annotations
from typing import TypeVar, Callable, Generic, Optional, Any
import random
import copy

T = TypeVar("T")
U = TypeVar("U")
K = TypeVar("K")


def first(items: list[T], fn: Callable[[T], bool] | None = None) -> T | None:
    if fn:
        return next((x for x in items if fn(x)), None)
    return items[0] if items else None


def last(items: list[T], fn: Callable[[T], bool] | None = None) -> T | None:
    if fn:
        found = None
        for x in items:
            if fn(x):
                found = x
        return found
    return items[-1] if items else None


def chunk(items: list[T], size: int) -> list[list[T]]:
    if size <= 0 or not items:
        return []
    return [items[i:i + size] for i in range(0, len(items), size)]


def group_by(items: list[T], fn: Callable[[T], K]) -> dict[K, list[T]]:
    result: dict[Any, list] = {}
    for item in items:
        result.setdefault(fn(item), []).append(item)
    return result


def key_by(items: list[T], fn: Callable[[T], K]) -> dict[K, T]:
    return {fn(item): item for item in items}


def unique(items: list[T]) -> list[T]:
    seen: set = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def unique_by(items: list[T], fn: Callable[[T], K]) -> list[T]:
    seen: set = set()
    out = []
    for item in items:
        k = fn(item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def diff(a: list[T], b: list[T]) -> list[T]:
    b_set = set(b)
    return [x for x in a if x not in b_set]


def intersect(a: list[T], b: list[T]) -> list[T]:
    b_set = set(b)
    return [x for x in a if x in b_set]


def partition(items: list[T], fn: Callable[[T], bool]) -> tuple[list[T], list[T]]:
    yes, no = [], []
    for item in items:
        (yes if fn(item) else no).append(item)
    return yes, no


def shuffle(items: list[T]) -> list[T]:
    out = list(items)
    random.shuffle(out)
    return out


def random_sample(items: list[T], n: int) -> list[T]:
    return random.sample(items, min(n, len(items)))


# Dot-notation helpers
def get(m: dict, key: str, default: Any = None) -> Any:
    cur = m
    for seg in key.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return default
        cur = cur[seg]
    return cur


def set_value(m: dict, key: str, value: Any) -> None:
    parts = key.split(".", 1)
    if len(parts) == 1:
        m[key] = value
        return
    head, rest = parts
    if not isinstance(m.get(head), dict):
        m[head] = {}
    set_value(m[head], rest, value)


def has(m: dict, key: str) -> bool:
    return get(m, key, _sentinel := object()) is not _sentinel


def forget(m: dict, key: str) -> None:
    parts = key.split(".", 1)
    if len(parts) == 1:
        m.pop(key, None)
        return
    head, rest = parts
    if isinstance(m.get(head), dict):
        forget(m[head], rest)


def dot(m: dict, prefix: str = "") -> dict:
    out: dict = {}
    for k, v in m.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(dot(v, full_key))
        else:
            out[full_key] = v
    return out


def merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            merge(dst[k], v)
        else:
            dst[k] = v
    return dst
```

---

## Laravel comparison

| Laravel `Arr::` | `arr.` Go function | Notes |
|---|---|---|
| `Arr::first($a, $fn)` | `arr.First(items, fn)` | Returns `(T, bool)` instead of `null` |
| `Arr::last($a, $fn)` | `arr.Last(items, fn)` | Same |
| `Arr::map($a, $fn)` | `arr.Map(items, fn)` | `fn` receives `(value, index)` |
| `Arr::filter($a, $fn)` | `arr.Filter(items, fn)` | |
| `Arr::reject($a, $fn)` | `arr.Reject(items, fn)` | |
| `Arr::reduce($a, $fn, $init)` | `arr.Reduce(items, fn, init)` | `fn` receives `(carry, item, index)` |
| `Arr::pluck($a, 'field')` | `arr.Pluck(items, fn)` | Uses a function instead of a key string |
| `Arr::unique($a)` | `arr.Unique(items)` | |
| `Arr::diff($a, $b)` | `arr.Diff(a, b)` | |
| `Arr::intersect($a, $b)` | `arr.Intersect(a, b)` | |
| `Arr::chunk($a, $size)` | `arr.Chunk(items, size)` | |
| `Arr::collapse($a)` | `arr.Collapse(items)` | |
| `Arr::flatten($a)` | `arr.Flatten(items)` | Any depth via `[]any` |
| `Arr::shuffle($a)` | `arr.Shuffle(items)` | |
| `Arr::random($a, $n)` | `arr.Random(items, n)` | |
| `Arr::sort($a)` | `arr.Sort(items, less)` | Requires explicit comparator |
| `Arr::groupBy($a, $fn)` | `arr.GroupBy(items, fn)` | |
| `Arr::keyBy($a, $fn)` | `arr.KeyBy(items, fn)` | |
| `Arr::partition($a, $fn)` | `arr.Partition(items, fn)` | |
| `Arr::zip($a, $b)` | `arr.Zip(a, b)` | Returns `[]Pair[A,B]` |
| `Arr::combine($keys, $vals)` | `arr.Combine(keys, vals)` | Returns `(map, error)` |
| `Arr::dot($m)` | `arr.Dot(m)` | Flatten nested map |
| `Arr::undot($m)` | `arr.Undot(m)` | Expand flat map |
| `Arr::get($m, $key, $default)` | `arr.Get(m, key, def...)` | |
| `Arr::set($m, $key, $value)` | `arr.Set(m, key, value)` | In-place |
| `Arr::has($m, $key)` | `arr.Has(m, key)` | |
| `Arr::hasAll($m, $keys)` | `arr.HasAll(m, keys...)` | |
| `Arr::hasAny($m, $keys)` | `arr.HasAny(m, keys...)` | |
| `Arr::forget($m, $key)` | `arr.Forget(m, key)` | In-place |
| `Arr::only($m, $keys)` | `arr.Only(m, keys...)` | Top-level keys only |
| `Arr::except($m, $keys)` | `arr.Except(m, keys...)` | Top-level keys only |
| `array_merge(…)` deep | `arr.Merge(dst, src)` | Recursive map merge |
