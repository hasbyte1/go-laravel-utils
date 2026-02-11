# collections

A generic, immutable-by-default `Collection[T]` type and type-safe package-level
helper functions for Go, inspired by
[Laravel's Illuminate/Collections](https://github.com/laravel/framework/tree/12.x/src/Illuminate/Collections).

```
go get github.com/hasbyte1/go-laravel-utils/collections
```

Requires **Go 1.21+**. No external dependencies.

---

## Table of Contents

- [Core concepts](#core-concepts)
- [Constructors](#constructors)
- [Accessors](#accessors)
- [Iteration](#iteration)
- [Searching](#searching)
- [Filtering](#filtering)
- [Transformation](#transformation)
- [Type-transforming functions](#type-transforming-functions)
- [Sorting & randomisation](#sorting--randomisation)
- [Add / remove](#add--remove)
- [Slicing & pagination](#slicing--pagination)
- [Aggregation](#aggregation)
- [Grouping & partitioning](#grouping--partitioning)
- [String helpers](#string-helpers)
- [Conditional pipeline](#conditional-pipeline)
- [Macros — runtime extension](#macros--runtime-extension)
- [Enumerable interface](#enumerable-interface)
- [Edge cases](#edge-cases)
- [Porting guide](#porting-guide)
- [Laravel comparison](#laravel-comparison)

---

## Core concepts

### Immutability

Every method that transforms a collection returns a **new** `*Collection[T]`.
The original is never modified. This means:

- Collections are safe to share between goroutines without locks.
- Chaining never produces side-effects.
- You can branch a pipeline at any point.

```go
original := collections.New(1, 2, 3, 4, 5)
evens    := original.Filter(func(n, _ int) bool { return n%2 == 0 })
odds     := original.Filter(func(n, _ int) bool { return n%2 != 0 })
// original is still [1 2 3 4 5]
```

### Generics — same-type vs type-transforming

Go generics do not allow methods to introduce new type parameters. This means:

| Operation | Return type | How |
|---|---|---|
| `Filter`, `Sort`, `Reverse`, … | `*Collection[T]` (same type) | Method on `*Collection[T]` |
| `Map`, `GroupBy`, `Pluck`, … | `*Collection[U]` (different type) | Package-level function |

Methods that must return `Collection[any]` (losing compile-time safety) also exist as
convenience wrappers for quick scripting. Always prefer the typed package-level functions
in production code.

---

## Constructors

```go
// From a variadic list (items are copied):
c := collections.New(1, 2, 3, 4, 5)

// From an existing slice (slice is copied — mutations do not affect the collection):
s := []string{"a", "b", "c"}
c := collections.From(s)
s[0] = "z"  // c still starts with "a"

// Empty collection:
c := collections.Empty[int]()
```

---

## Accessors

```go
c := collections.New(10, 20, 30)

c.All()        // []int{10, 20, 30} — copy
c.ToSlice()    // alias for All()
c.Count()      // 3
c.IsEmpty()    // false
c.IsNotEmpty() // true
c.Keys()       // []int{0, 1, 2}
c.Values()     // clean copy of the collection

v, ok := c.Get(1)   // 20, true
v, ok  = c.Get(99)  // 0,  false
c.Has(1)            // true
c.Has(99)           // false

b, err := c.ToJSON()  // []byte(`[10,20,30]`)
fmt.Println(c)        // [10,20,30]   (implements fmt.Stringer)
```

---

## Iteration

```go
c := collections.New("a", "b", "c")

// Each — iterate without transforming
c.Each(func(s string, i int) {
    fmt.Printf("[%d] %s\n", i, s)
})

// Tap — side-effect in a chain (e.g. logging), then continue
result := collections.New(1, 2, 3).
    Tap(func(c *collections.Collection[int]) {
        fmt.Println("before filter:", c)
    }).
    Filter(func(n, _ int) bool { return n > 1 }).
    Tap(func(c *collections.Collection[int]) {
        fmt.Println("after filter:", c)
    })

// Dump — print to stdout and continue chaining
collections.New(1, 2, 3).
    Filter(func(n, _ int) bool { return n%2 != 0 }).
    Dump(). // prints [1,3]
    Reverse()
```

---

## Searching

```go
c := collections.New(10, 20, 30, 40, 50)

// First / Last — no predicate
v, ok := c.First() // 10, true
v, ok  = c.Last()  // 50, true
_, ok  = collections.Empty[int]().First() // 0, false

// First / Last — with predicate
v, ok = c.First(func(n int) bool { return n > 25 }) // 30, true
v, ok = c.Last(func(n int) bool { return n < 35 })  // 30, true

// FirstOrFail / LastOrFail
v, err := c.FirstOrFail(func(n int) bool { return n > 100 })
// → ErrNoMatchingItems
v, err  = c.LastOrFail(func(n int) bool { return n%20 == 0 })
// → 40, nil

// Contains
c.Contains(func(n int) bool { return n == 30 }) // true

// Search — returns index or -1
idx := c.Search(func(n int) bool { return n == 30 }) // 2
idx  = c.Search(func(n int) bool { return n > 100 }) // -1
```

---

## Filtering

```go
c := collections.New(1, 2, 3, 4, 5, 6)

// Filter — keep matching
evens := c.Filter(func(n, _ int) bool { return n%2 == 0 })
// → [2 4 6]

// Reject / WhereNot — remove matching
odds := c.Reject(func(n, _ int) bool { return n%2 == 0 })
// → [1 3 5]

// Where / WhereNot are aliases:
c.Where(func(n, _ int) bool { return n > 3 })    // → [4 5 6]
c.WhereNot(func(n, _ int) bool { return n > 3 }) // → [1 2 3]

// Index-aware filtering
c.Filter(func(n, idx int) bool { return idx%2 == 0 }) // even-indexed items
// → [1 3 5]  (indices 0, 2, 4)

// Unique — remove duplicates
collections.New(1, 2, 2, 3, 3, 3).Unique(nil)
// → [1 2 3]

// Unique with key function
type Person struct{ Name, Dept string }
people := collections.New(
    Person{"Alice", "Eng"},
    Person{"Bob",   "Eng"},
    Person{"Carol", "HR"},
)
firstPerDept := people.Unique(func(p Person) any { return p.Dept })
// → [{Alice Eng} {Carol HR}]

// Diff — items in c not in other (needs key fn)
a := collections.New(1, 2, 3, 4, 5)
b := collections.New(2, 4)
key := func(n int) any { return n }
a.Diff(b, key) // → [1 3 5]

// Intersect
a.Intersect(b, key) // → [2 4]
```

---

## Transformation

### Map (returns `Collection[any]`)

```go
// Quick, untyped — fine for scripting
doubled := collections.New(1, 2, 3).Map(func(n, _ int) any { return n * 2 })
// → Collection[any]{2, 4, 6}
```

For typed output use the package-level `Map` function (see below).

### Reduce (same-type)

```go
// Accumulate within the same type
sum := collections.New(1, 2, 3, 4, 5).
    Reduce(func(carry, n int) int { return carry + n }, 0)
// → 15
```

For cross-type reduction use the package-level `Reduce` function.

### Pluck (returns `Collection[any]`)

```go
type Item struct{ Name string; Price float64 }
items := collections.New(Item{"Widget", 9.99}, Item{"Gadget", 24.99})
prices := items.Pluck(func(i Item) any { return i.Price })
// → Collection[any]{9.99, 24.99}
```

---

## Type-transforming functions

These are **package-level** because Go methods cannot introduce new type parameters.

### Map

```go
// int → string
strs := collections.Map(
    collections.New(1, 2, 3),
    func(n, _ int) string { return strconv.Itoa(n) },
)
strs.All() // []string{"1", "2", "3"}

// Struct → field
type User struct{ ID int; Name string }
users := collections.New(User{1, "Alice"}, User{2, "Bob"})
names := collections.Map(users, func(u User, _ int) string { return u.Name })
names.All() // []string{"Alice", "Bob"}
```

### FlatMap

```go
// Each item produces multiple outputs, which are flattened one level
sentences := collections.New("hello world", "foo bar baz")
words := collections.FlatMap(sentences, func(s string, _ int) []string {
    return strings.Fields(s)
})
words.All() // []string{"hello", "world", "foo", "bar", "baz"}
```

### Reduce (cross-type)

```go
// []int → string
csv := collections.Reduce(
    collections.New(1, 2, 3, 4, 5),
    func(acc string, n, _ int) string {
        if acc == "" { return strconv.Itoa(n) }
        return acc + "," + strconv.Itoa(n)
    },
    "",
)
// → "1,2,3,4,5"

// Count words
words := collections.New("go", "is", "go", "fast")
freq := collections.Reduce(words, func(m map[string]int, w string, _ int) map[string]int {
    m[w]++
    return m
}, map[string]int{})
// → map[go:2 is:1 fast:1]
```

### Pluck

```go
type Product struct{ ID int; Name string; Price float64 }
catalog := collections.New(
    Product{1, "Widget", 9.99},
    Product{2, "Gadget", 24.99},
    Product{3, "Doohickey", 4.99},
)
prices := collections.Pluck(catalog, func(p Product) float64 { return p.Price })
prices.All() // []float64{9.99, 24.99, 4.99}
```

### GroupBy

```go
type Order struct{ ID int; Status string; Amount float64 }
orders := collections.New(
    Order{1, "pending",   50},
    Order{2, "completed", 120},
    Order{3, "pending",   30},
    Order{4, "completed", 80},
)

byStatus := collections.GroupBy(orders, func(o Order) string { return o.Status })
// map[string]*Collection[Order]
// byStatus["pending"]   → 2 orders
// byStatus["completed"] → 2 orders

// Summarise each group
for status, group := range byStatus {
    total := group.Sum(func(o Order) float64 { return o.Amount })
    fmt.Printf("%s: $%.2f\n", status, total)
}
```

### KeyBy

```go
byID := collections.KeyBy(users, func(u User) int { return u.ID })
// map[int]User
user := byID[42] // O(1) lookup
```

### Zip

```go
keys   := collections.New("a", "b", "c")
values := collections.New(1, 2, 3)
pairs  := collections.Zip(keys, values)
// → Collection[Pair[string, int]]

pairs.Each(func(p collections.Pair[string, int], _ int) {
    fmt.Printf("%s → %d\n", p.First, p.Second)
})
// a → 1
// b → 2
// c → 3
```

### Combine

```go
headers := []string{"Content-Type", "Authorization"}
values  := []string{"application/json", "Bearer token123"}

m, err := collections.Combine(headers, values)
// map[string]string
// m["Content-Type"] = "application/json"
```

### Collapse / Flatten

```go
// Collapse: one level
nested := collections.New([]int{1, 2}, []int{3, 4}, []int{5})
flat   := collections.Collapse(nested)
flat.All() // [1 2 3 4 5]

// FlattenDeep: arbitrary depth (Collection[any])
deep := collections.New[any](1, []any{2, 3, []any{4, 5}})
all  := collections.FlattenDeep(deep)
all.All() // [1 2 3 4 5]
```

---

## Sorting & randomisation

```go
c := collections.New(5, 3, 1, 4, 2)

// Sort with a less function (stable sort)
c.Sort(func(a, b int) bool { return a < b })  // [1 2 3 4 5]
c.Sort(func(a, b int) bool { return a > b })  // [5 4 3 2 1]

// SortBy — extract a float64 key
type Employee struct{ Name string; Salary float64 }
employees := collections.New(
    Employee{"Alice", 75000},
    Employee{"Bob",   60000},
    Employee{"Carol", 90000},
)
employees.SortBy(func(e Employee) float64 { return e.Salary })
// [Bob Alice Carol]
employees.SortByDesc(func(e Employee) float64 { return e.Salary })
// [Carol Alice Bob]

// Reverse
collections.New(1, 2, 3).Reverse() // [3 2 1]

// Shuffle — random order, original unchanged
shuffled := collections.New(1, 2, 3, 4, 5).Shuffle()

// Random — n random items (without replacement)
three := collections.New(1, 2, 3, 4, 5).Random(3)
```

---

## Add / remove

All of these return a **new** collection; the original is unchanged.

```go
c := collections.New(2, 3, 4)

c.Push(5, 6)       // [2 3 4 5 6]
c.Append(5, 6)     // alias for Push
c.Prepend(0, 1)    // [0 1 2 3 4]

// Pop — remove last, returns (item, rest, ok)
last, rest, ok := c.Pop()  // 4, [2 3], true
_, _, ok = collections.Empty[int]().Pop() // 0, empty, false

// Shift — remove first
first, rest, ok := c.Shift() // 2, [3 4], true

// Pull — remove by index
item, rest, ok := c.Pull(1) // 3, [2 4], true

// Forget — remove by index, ignore result
c.Forget(0) // [3 4]
```

---

## Slicing & pagination

```go
c := collections.New(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

// Take — first n
c.Take(3)  // [1 2 3]
// Take negative — last n
c.Take(-3) // [8 9 10]

// Skip — skip first n
c.Skip(3)  // [4 5 6 7 8 9 10]
// Skip negative — skip last n
c.Skip(-3) // [1 2 3 4 5 6 7]

// Slice(offset, length)  — negative offset counts from end; -1 length = to end
c.Slice(2, 3)   // [3 4 5]
c.Slice(-3, -1) // [8 9 10]   (last 3, to end)
c.Slice(0, -1)  // [1..10]    (full)

// Chunk — split into groups of n, returns [][]T
c.Chunk(3)
// [[1 2 3] [4 5 6] [7 8 9] [10]]

// Wrap each chunk in a Collection for further processing
for _, chunk := range c.Chunk(3) {
    sub := collections.From(chunk)
    fmt.Println(sub.Sum(func(n int) float64 { return float64(n) }))
}
// 6, 15, 24, 10

// Predicate-based take/skip
c.TakeUntil(func(n int) bool { return n >= 5 }) // [1 2 3 4]
c.TakeWhile(func(n int) bool { return n < 5 })  // [1 2 3 4]
c.SkipUntil(func(n int) bool { return n >= 5 }) // [5 6 7 8 9 10]
c.SkipWhile(func(n int) bool { return n < 5 })  // [5 6 7 8 9 10]
```

---

## Aggregation

```go
type Sale struct{ Product string; Amount float64 }
sales := collections.New(
    Sale{"Widget", 9.99},
    Sale{"Gadget", 24.99},
    Sale{"Widget", 14.99},
)

sales.Sum(func(s Sale) float64 { return s.Amount })     // 49.97
sales.Average(func(s Sale) float64 { return s.Amount }) // 16.66
collections.Empty[Sale]().Average(func(s Sale) float64 { return s.Amount }) // 0

minSale, ok := sales.Min(func(s Sale) float64 { return s.Amount }) // {Widget 9.99}, true
maxSale, ok  := sales.Max(func(s Sale) float64 { return s.Amount }) // {Gadget 24.99}, true
_, ok = collections.Empty[Sale]().Min(func(s Sale) float64 { return s.Amount }) // _, false
```

---

## Grouping & partitioning

```go
// GroupBy — returns map[any]*Collection[T]
c := collections.New(1, 2, 3, 4, 5, 6)
groups := c.GroupBy(func(n int) any {
    if n%2 == 0 { return "even" }
    return "odd"
})
groups["even"].All() // [2 4 6]
groups["odd"].All()  // [1 3 5]

// KeyBy — last item wins on duplicate keys
type User struct{ ID int; Name string }
users := collections.New(User{1, "Alice"}, User{2, "Bob"}, User{1, "Alex"})
keyed := users.KeyBy(func(u User) any { return u.ID })
keyed[1] // User{1, "Alex"} — last write wins

// Partition — two collections: pass, fail
evens, odds := collections.New(1, 2, 3, 4, 5).Partition(func(n int) bool {
    return n%2 == 0
})
evens.All() // [2 4]
odds.All()  // [1 3 5]
```

---

## String helpers

```go
// Implode — join with separator
collections.New(1, 2, 3).Implode(", ", strconv.Itoa)   // "1, 2, 3"
collections.New("go", "is", "great").Implode("-", func(s string) string { return s })
// "go-is-great"

// Flip — map value string → index
flip := collections.New("a", "b", "c").Flip()
// map[string]int{"a": 0, "b": 1, "c": 2}
flip["b"] // 1
```

---

## Conditional pipeline

```go
userIsAdmin := true

result := collections.New(1, 2, 3, 4, 5).
    When(userIsAdmin, func(c *collections.Collection[int]) *collections.Collection[int] {
        return c.Push(99) // admins see a bonus item
    }).
    Unless(userIsAdmin, func(c *collections.Collection[int]) *collections.Collection[int] {
        return c.Take(3) // non-admins see only 3
    })

// WhenEmpty / WhenNotEmpty
defaults := collections.Empty[string]().WhenEmpty(func(c *collections.Collection[string]) *collections.Collection[string] {
    return c.Push("(no items)")
})
defaults.All() // ["(no items)"]

nonEmpty := collections.New("x", "y").WhenEmpty(func(c *collections.Collection[string]) *collections.Collection[string] {
    return c.Push("(no items)")
})
nonEmpty.All() // ["x", "y"] — unchanged
```

---

## Macros — runtime extension

Macros let you register named custom operations and call them on any collection instance
without modifying the `Collection` type. This mirrors Laravel's `Collection::macro()`.

```go
// Register once, typically in init() or application bootstrap
collections.RegisterMacro("sumInt", func(col any, _ ...any) any {
    c := col.(*collections.Collection[int])
    return int(c.Sum(func(n int) float64 { return float64(n) }))
})

collections.RegisterMacro("multiply", func(col any, args ...any) any {
    c      := col.(*collections.Collection[int])
    factor := args[0].(int)
    return collections.Map(c, func(n, _ int) int { return n * factor })
})

// Check existence
collections.HasMacro("sumInt")   // true
collections.HasMacro("missing")  // false

// Call
result, err := collections.New(1, 2, 3, 4, 5).Macro("sumInt")
// result.(int) == 15

doubled, _ := collections.New(1, 2, 3).Macro("multiply", 2)
// doubled.(*collections.Collection[int]).All() == [2 4 6]

// Calling a non-existent macro
_, err = collections.New(1).Macro("nonexistent")
// errors.Is(err, collections.ErrMacroNotFound) == true

// In tests, clean up with:
collections.FlushMacros()
```

---

## Enumerable interface

Accept `collections.Enumerable[T]` instead of `*collections.Collection[T]` in your
own functions and interfaces. This decouples callers from the concrete type and enables
substituting alternative implementations.

```go
func printAll[T any](e collections.Enumerable[T]) {
    fmt.Printf("count=%d items=%v\n", e.Count(), e.All())
}

printAll(collections.New(1, 2, 3))

// Implement the interface yourself (minimal):
type myList[T any] struct{ items []T }

func (m *myList[T]) All() []T                                { return m.items }
func (m *myList[T]) Count() int                             { return len(m.items) }
func (m *myList[T]) Each(fn func(T, int))                   { for i, v := range m.items { fn(v, i) } }
func (m *myList[T]) Filter(fn func(T, int) bool) *collections.Collection[T] {
    // delegate to the real implementation
    return collections.From(m.items).Filter(fn)
}
// ... remaining methods
```

---

## Edge cases

| Scenario | Behaviour |
|---|---|
| `New()` / `Empty[T]()` | Zero-length collection, all operations safe |
| `nil` slice passed to `From` | Returns empty collection |
| `First` / `Last` on empty | Returns zero value + `false` |
| `First` / `Last` predicate with no match | Returns zero value + `false` |
| `Get(-1)` or out-of-range | Returns zero value + `false` |
| `Pop` / `Shift` on empty | Returns zero value, unchanged collection, `false` |
| `Pull` / `Forget` out of range | Returns unchanged collection |
| `Chunk(0)` | Returns `[][]T{}` |
| `Take(n)` where n > Count() | Returns all items |
| `Skip(n)` where n >= Count() | Returns empty |
| `Random(n)` where n >= Count() | Returns shuffled copy of all |
| `Unique(nil)` | Uses `fmt.Sprintf("%v", item)` as key |
| `Average` on empty | Returns `0` |
| `Min` / `Max` on empty | Returns zero value + `false` |

---

## Porting guide

### Node.js / TypeScript

The Collection API maps cleanly to a JavaScript class with method chaining:

```ts
class Collection<T> {
    private readonly _items: T[];

    constructor(items: T[] = []) {
        this._items = [...items]; // immutable copy
    }

    static of<T>(...items: T[]): Collection<T> { return new Collection(items); }
    static from<T>(items: T[]): Collection<T>  { return new Collection(items); }
    static empty<T>(): Collection<T>            { return new Collection<T>(); }

    all(): T[]     { return [...this._items]; }
    count(): number { return this._items.length; }
    isEmpty(): boolean    { return this._items.length === 0; }
    isNotEmpty(): boolean { return this._items.length > 0; }

    filter(fn: (item: T, index: number) => boolean): Collection<T> {
        return new Collection(this._items.filter(fn));
    }
    reject(fn: (item: T, index: number) => boolean): Collection<T> {
        return this.filter((item, i) => !fn(item, i));
    }
    map<U>(fn: (item: T, index: number) => U): Collection<U> {
        return new Collection(this._items.map(fn));
    }
    flatMap<U>(fn: (item: T, index: number) => U[]): Collection<U> {
        return new Collection(this._items.flatMap(fn));
    }
    reduce<U>(fn: (acc: U, item: T, index: number) => U, initial: U): U {
        return this._items.reduce(fn, initial);
    }
    first(fn?: (item: T) => boolean): T | undefined {
        return fn ? this._items.find(fn) : this._items[0];
    }
    last(fn?: (item: T) => boolean): T | undefined {
        const a = fn ? this._items.filter(fn) : this._items;
        return a[a.length - 1];
    }
    sort(compareFn: (a: T, b: T) => number): Collection<T> {
        return new Collection([...this._items].sort(compareFn));
    }
    reverse(): Collection<T> {
        return new Collection([...this._items].reverse());
    }
    take(n: number): Collection<T> {
        if (n < 0) return new Collection(this._items.slice(n));
        return new Collection(this._items.slice(0, n));
    }
    skip(n: number): Collection<T> {
        if (n < 0) return new Collection(this._items.slice(0, this._items.length + n));
        return new Collection(this._items.slice(n));
    }
    chunk(size: number): T[][] {
        const out: T[][] = [];
        for (let i = 0; i < this._items.length; i += size)
            out.push(this._items.slice(i, i + size));
        return out;
    }
    unique<K>(keyFn?: (item: T) => K): Collection<T> {
        const seen = new Set<K | string>();
        return this.filter(item => {
            const k = keyFn ? keyFn(item) : JSON.stringify(item);
            if (seen.has(k as K)) return false;
            seen.add(k as K);
            return true;
        });
    }
    groupBy<K extends string | number | symbol>(
        keyFn: (item: T) => K
    ): Record<K, Collection<T>> {
        const groups = {} as Record<K, Collection<T>>;
        this._items.forEach(item => {
            const k = keyFn(item);
            if (!groups[k]) groups[k] = Collection.empty<T>();
            (groups[k] as any)._items.push(item);
        });
        return groups;
    }
    sum(fn: (item: T) => number): number { return this._items.reduce((a, b) => a + fn(b), 0); }
    each(fn: (item: T, index: number) => void): this { this._items.forEach(fn); return this; }
    toArray(): T[] { return this.all(); }
    toJSON(): string { return JSON.stringify(this._items); }
}

// Usage:
const result = Collection.of(1, 2, 3, 4, 5, 6)
    .filter((n) => n % 2 === 0)
    .map((n) => n * n)
    .sum((n) => n); // 4 + 16 + 36 = 56
```

### Python

```python
from __future__ import annotations
import json, random
from typing import TypeVar, Generic, Callable, Iterator, Any
from functools import reduce as _reduce

T = TypeVar("T")
U = TypeVar("U")

class Collection(Generic[T]):
    """Immutable-by-default fluent wrapper around a Python list."""

    def __init__(self, items: list[T] = None) -> None:
        self._items: list[T] = list(items or [])  # copy

    @classmethod
    def of(cls, *items: T) -> "Collection[T]":
        return cls(list(items))

    @classmethod
    def from_list(cls, items: list[T]) -> "Collection[T]":
        return cls(list(items))

    @classmethod
    def empty(cls) -> "Collection[Any]":
        return cls([])

    # ── Accessors ──────────────────────────────────────────────────────
    def all(self) -> list[T]:      return list(self._items)
    def to_list(self) -> list[T]:  return self.all()
    def count(self) -> int:         return len(self._items)
    def is_empty(self) -> bool:     return not self._items
    def is_not_empty(self) -> bool: return bool(self._items)
    def get(self, i: int) -> tuple[T | None, bool]:
        if 0 <= i < len(self._items):
            return self._items[i], True
        return None, False

    # ── Iteration ──────────────────────────────────────────────────────
    def each(self, fn: Callable[[T, int], None]) -> "Collection[T]":
        for i, item in enumerate(self._items):
            fn(item, i)
        return self
    def tap(self, fn: Callable[["Collection[T]"], None]) -> "Collection[T]":
        fn(self); return self

    # ── Searching ──────────────────────────────────────────────────────
    def first(self, fn: Callable[[T], bool] = None) -> T | None:
        if fn:
            return next((x for x in self._items if fn(x)), None)
        return self._items[0] if self._items else None
    def last(self, fn: Callable[[T], bool] = None) -> T | None:
        items = [x for x in self._items if fn(x)] if fn else self._items
        return items[-1] if items else None
    def contains(self, fn: Callable[[T], bool]) -> bool:
        return any(fn(x) for x in self._items)
    def search(self, fn: Callable[[T], bool]) -> int:
        return next((i for i, x in enumerate(self._items) if fn(x)), -1)

    # ── Transformation ─────────────────────────────────────────────────
    def filter(self, fn: Callable[[T, int], bool]) -> "Collection[T]":
        return Collection([x for i, x in enumerate(self._items) if fn(x, i)])
    def reject(self, fn: Callable[[T, int], bool]) -> "Collection[T]":
        return self.filter(lambda x, i: not fn(x, i))
    def map(self, fn: Callable[[T, int], U]) -> "Collection[U]":
        return Collection([fn(x, i) for i, x in enumerate(self._items)])
    def flat_map(self, fn: Callable[[T, int], list[U]]) -> "Collection[U]":
        return Collection([y for i, x in enumerate(self._items) for y in fn(x, i)])
    def reduce(self, fn: Callable[[U, T, int], U], initial: U) -> U:
        result = initial
        for i, item in enumerate(self._items):
            result = fn(result, item, i)
        return result
    def unique(self, key_fn: Callable[[T], Any] = None) -> "Collection[T]":
        seen, out = set(), []
        for x in self._items:
            k = key_fn(x) if key_fn else str(x)
            if k not in seen:
                seen.add(k); out.append(x)
        return Collection(out)

    # ── Sorting ────────────────────────────────────────────────────────
    def sort(self, key: Callable[[T], Any], reverse: bool = False) -> "Collection[T]":
        return Collection(sorted(self._items, key=key, reverse=reverse))
    def reverse(self) -> "Collection[T]":
        return Collection(list(reversed(self._items)))
    def shuffle(self) -> "Collection[T]":
        out = list(self._items); random.shuffle(out); return Collection(out)
    def random(self, n: int) -> "Collection[T]":
        return Collection(random.sample(self._items, min(n, len(self._items))))

    # ── Slicing ────────────────────────────────────────────────────────
    def take(self, n: int) -> "Collection[T]":
        return Collection(self._items[n:] if n < 0 else self._items[:n])
    def skip(self, n: int) -> "Collection[T]":
        return Collection(self._items[:n] if n < 0 else self._items[n:])
    def chunk(self, size: int) -> list[list[T]]:
        return [self._items[i:i+size] for i in range(0, len(self._items), size)]
    def slice(self, offset: int, length: int = -1) -> "Collection[T]":
        s = self._items[offset:] if length < 0 else self._items[offset:offset+length]
        return Collection(s)

    # ── Aggregation ────────────────────────────────────────────────────
    def sum(self, fn: Callable[[T], float]) -> float:
        return sum(fn(x) for x in self._items)
    def average(self, fn: Callable[[T], float]) -> float:
        return self.sum(fn) / len(self._items) if self._items else 0
    def min(self, fn: Callable[[T], float]) -> T | None:
        return min(self._items, key=fn) if self._items else None
    def max(self, fn: Callable[[T], float]) -> T | None:
        return max(self._items, key=fn) if self._items else None

    # ── Grouping ───────────────────────────────────────────────────────
    def group_by(self, fn: Callable[[T], Any]) -> dict[Any, "Collection[T]"]:
        groups: dict = {}
        for x in self._items:
            k = fn(x)
            groups.setdefault(k, []).append(x)
        return {k: Collection(v) for k, v in groups.items()}
    def partition(self, fn: Callable[[T], bool]) -> tuple["Collection[T]", "Collection[T]"]:
        pass_, fail = [], []
        for x in self._items:
            (pass_ if fn(x) else fail).append(x)
        return Collection(pass_), Collection(fail)

    # ── Helpers ────────────────────────────────────────────────────────
    def implode(self, sep: str, fn: Callable[[T], str] = str) -> str:
        return sep.join(fn(x) for x in self._items)
    def when(self, cond: bool, fn: Callable[["Collection[T]"], "Collection[T]"]) -> "Collection[T]":
        return fn(self) if cond else self
    def to_json(self) -> str:
        return json.dumps(self._items)
    def __repr__(self) -> str:
        return f"Collection({self._items!r})"

# Standalone helpers
def cmap(c: Collection, fn):   return c.map(fn)
def group_by(c: Collection, fn): return c.group_by(fn)
def zip_collections(a: Collection, b: Collection):
    return Collection(list(zip(a.all(), b.all())))

# Usage:
result = (
    Collection.of(1, 2, 3, 4, 5, 6)
    .filter(lambda n, _: n % 2 == 0)
    .sort(key=lambda n: n, reverse=True)
    .take(2)
    .implode(", ", str)
)
# → "6, 4"
```

---

## Laravel comparison

| Laravel | Go (method) | Go (package fn) | Notes |
|---|---|---|---|
| `collect([1,2,3])` | `collections.New(1,2,3)` | — | |
| `$c->all()` | `c.All()` | — | |
| `$c->count()` | `c.Count()` | — | |
| `$c->filter(fn)` | `c.Filter(fn)` | — | fn receives `(item, index)` |
| `$c->reject(fn)` | `c.Reject(fn)` | — | |
| `$c->map(fn)` | `c.Map(fn)` → `any` | `collections.Map(c, fn)` | Use pkg fn for type safety |
| `$c->flatMap(fn)` | `c.FlatMap(fn)` → `any` | `collections.FlatMap(c, fn)` | |
| `$c->reduce(fn)` | `c.Reduce(fn, init)` | `collections.Reduce(c, fn, init)` | |
| `$c->pluck('name')` | `c.Pluck(fn)` → `any` | `collections.Pluck(c, fn)` | fn extracts field |
| `$c->groupBy('key')` | `c.GroupBy(fn)` → `map[any]*Col` | `collections.GroupBy(c, fn)` | typed keys via pkg fn |
| `$c->keyBy('id')` | `c.KeyBy(fn)` → `map[any]T` | `collections.KeyBy(c, fn)` | |
| `$c->zip($other)` | — | `collections.Zip(a, b)` | returns `Collection[Pair]` |
| `$c->combine($vals)` | — | `collections.Combine(keys, vals)` | |
| `$c->collapse()` | — | `collections.Collapse(c)` | c must be `Collection[[]T]` |
| `$c->flatten()` | — | `collections.Flatten(c)` / `FlattenDeep(c)` | |
| `$c->unique('key')` | `c.Unique(fn)` | — | fn extracts key; nil = fmt |
| `$c->diff($other)` | `c.Diff(other, fn)` | — | fn extracts comparable key |
| `$c->intersect($other)` | `c.Intersect(other, fn)` | — | |
| `$c->sort()` | `c.Sort(less)` | — | |
| `$c->sortBy('field')` | `c.SortBy(fn)` | — | fn extracts float64 |
| `$c->reverse()` | `c.Reverse()` | — | |
| `$c->shuffle()` | `c.Shuffle()` | — | |
| `$c->random(n)` | `c.Random(n)` | — | |
| `$c->take(n)` | `c.Take(n)` | — | negative → from end |
| `$c->skip(n)` | `c.Skip(n)` | — | |
| `$c->slice(offset, n)` | `c.Slice(offset, n)` | — | |
| `$c->chunk(n)` | `c.Chunk(n)` → `[][]T` | — | returns plain slice |
| `$c->sum('field')` | `c.Sum(fn)` | — | |
| `$c->avg('field')` | `c.Average(fn)` | — | |
| `$c->min('field')` | `c.Min(fn)` | — | returns (item, bool) |
| `$c->max('field')` | `c.Max(fn)` | — | |
| `$c->partition(fn)` | `c.Partition(fn)` | — | |
| `$c->first(fn)` | `c.First(fn)` | — | |
| `$c->last(fn)` | `c.Last(fn)` | — | |
| `$c->contains(fn)` | `c.Contains(fn)` | — | |
| `$c->search(fn)` | `c.Search(fn)` | — | returns int |
| `$c->push($val)` | `c.Push(val)` | — | returns new |
| `$c->prepend($val)` | `c.Prepend(val)` | — | returns new |
| `$c->pop()` | `c.Pop()` | — | returns (val, rest, ok) |
| `$c->shift()` | `c.Shift()` | — | |
| `$c->pull($key)` | `c.Pull(idx)` | — | |
| `$c->forget($key)` | `c.Forget(idx)` | — | |
| `$c->implode(', ')` | `c.Implode(", ", fn)` | — | fn converts T → string |
| `$c->flip()` | `c.Flip()` | — | returns `map[string]int` |
| `$c->when(cond, fn)` | `c.When(cond, fn)` | — | |
| `$c->unless(cond, fn)` | `c.Unless(cond, fn)` | — | |
| `$c->macro('name', fn)` | `collections.RegisterMacro` | — | global registry |
| `$c->each(fn)` | `c.Each(fn)` | — | |
| `$c->tap(fn)` | `c.Tap(fn)` | — | |
| `$c->dd()` | `c.Dump()` | — | prints, returns self |
| `$c->toArray()` | `c.ToSlice()` | — | |
| `$c->toJson()` | `c.ToJSON()` | — | |
