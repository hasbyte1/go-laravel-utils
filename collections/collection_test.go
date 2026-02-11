package collections_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/collections"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func ints(ns ...int) *collections.Collection[int] { return collections.New(ns...) }

func assertSlice[T comparable](t *testing.T, got, want []T) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slice length: got %d want %d  (got=%v want=%v)", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %v want %v", i, got[i], want[i])
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructors
// ─────────────────────────────────────────────────────────────────────────────

func TestNew(t *testing.T) {
	c := collections.New(1, 2, 3)
	assertSlice(t, c.All(), []int{1, 2, 3})
}

func TestFrom(t *testing.T) {
	s := []string{"a", "b", "c"}
	c := collections.From(s)
	s[0] = "z" // mutate original – should not affect the collection
	if c.All()[0] != "a" {
		t.Fatal("From did not copy the slice")
	}
}

func TestEmpty(t *testing.T) {
	c := collections.Empty[int]()
	if c.Count() != 0 {
		t.Fatal("empty collection should have Count 0")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessors
// ─────────────────────────────────────────────────────────────────────────────

func TestCount(t *testing.T) {
	if ints(1, 2, 3).Count() != 3 {
		t.Fatal("Count failed")
	}
}

func TestIsEmpty(t *testing.T) {
	if !collections.Empty[int]().IsEmpty() {
		t.Fatal("expected empty")
	}
	if ints(1).IsEmpty() {
		t.Fatal("should not be empty")
	}
}

func TestIsNotEmpty(t *testing.T) {
	if !ints(1).IsNotEmpty() {
		t.Fatal("expected not empty")
	}
}

func TestGet(t *testing.T) {
	c := ints(10, 20, 30)
	v, ok := c.Get(1)
	if !ok || v != 20 {
		t.Fatalf("Get(1) = %v, %v; want 20, true", v, ok)
	}
	_, ok = c.Get(99)
	if ok {
		t.Fatal("Get out of range should return false")
	}
	_, ok = c.Get(-1)
	if ok {
		t.Fatal("Get negative index should return false")
	}
}

func TestHas(t *testing.T) {
	c := ints(1, 2, 3)
	if !c.Has(0) || !c.Has(2) {
		t.Fatal("Has failed for valid index")
	}
	if c.Has(-1) || c.Has(3) {
		t.Fatal("Has should return false for out-of-range")
	}
}

func TestKeys(t *testing.T) {
	assertSlice(t, ints(10, 20, 30).Keys(), []int{0, 1, 2})
}

func TestToJSON(t *testing.T) {
	b, err := ints(1, 2, 3).ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	var got []int
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	assertSlice(t, got, []int{1, 2, 3})
}

func TestString(t *testing.T) {
	s := ints(1, 2, 3).String()
	if s != "[1,2,3]" {
		t.Fatalf("String() = %q; want [1,2,3]", s)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Iteration
// ─────────────────────────────────────────────────────────────────────────────

func TestEach(t *testing.T) {
	sum := 0
	ints(1, 2, 3, 4).Each(func(n, _ int) { sum += n })
	if sum != 10 {
		t.Fatalf("Each sum = %d; want 10", sum)
	}
}

func TestTap(t *testing.T) {
	var seen int
	result := ints(1, 2, 3).
		Tap(func(c *collections.Collection[int]) { seen = c.Count() }).
		Count()
	if seen != 3 || result != 3 {
		t.Fatal("Tap failed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Search
// ─────────────────────────────────────────────────────────────────────────────

func TestFirst(t *testing.T) {
	c := ints(1, 2, 3, 4)

	v, ok := c.First()
	if !ok || v != 1 {
		t.Fatalf("First() = %v, %v; want 1, true", v, ok)
	}

	v, ok = c.First(func(n int) bool { return n > 2 })
	if !ok || v != 3 {
		t.Fatalf("First with predicate = %v, %v; want 3, true", v, ok)
	}

	_, ok = collections.Empty[int]().First()
	if ok {
		t.Fatal("First on empty should return false")
	}

	_, ok = c.First(func(n int) bool { return n > 100 })
	if ok {
		t.Fatal("First with non-matching predicate should return false")
	}
}

func TestFirstOrFail(t *testing.T) {
	_, err := ints(1, 2, 3).FirstOrFail(func(n int) bool { return n > 5 })
	if err == nil {
		t.Fatal("expected ErrNoMatchingItems")
	}
	v, err := ints(1, 2, 3).FirstOrFail(func(n int) bool { return n == 2 })
	if err != nil || v != 2 {
		t.Fatalf("FirstOrFail = %v, %v; want 2, nil", v, err)
	}
}

func TestLast(t *testing.T) {
	c := ints(1, 2, 3, 4)

	v, ok := c.Last()
	if !ok || v != 4 {
		t.Fatalf("Last() = %v, %v; want 4, true", v, ok)
	}

	v, ok = c.Last(func(n int) bool { return n < 3 })
	if !ok || v != 2 {
		t.Fatalf("Last with predicate = %v, %v; want 2, true", v, ok)
	}

	_, ok = collections.Empty[int]().Last()
	if ok {
		t.Fatal("Last on empty should return false")
	}
}

func TestContains(t *testing.T) {
	c := ints(1, 2, 3)
	if !c.Contains(func(n int) bool { return n == 2 }) {
		t.Fatal("Contains should be true")
	}
	if c.Contains(func(n int) bool { return n == 99 }) {
		t.Fatal("Contains should be false")
	}
}

func TestSearch(t *testing.T) {
	c := ints(10, 20, 30)
	if idx := c.Search(func(n int) bool { return n == 20 }); idx != 1 {
		t.Fatalf("Search = %d; want 1", idx)
	}
	if idx := c.Search(func(n int) bool { return n == 99 }); idx != -1 {
		t.Fatalf("Search missing = %d; want -1", idx)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Transformation
// ─────────────────────────────────────────────────────────────────────────────

func TestFilter(t *testing.T) {
	got := ints(1, 2, 3, 4, 5).Filter(func(n, _ int) bool { return n%2 == 0 }).All()
	assertSlice(t, got, []int{2, 4})
}

func TestReject(t *testing.T) {
	got := ints(1, 2, 3, 4, 5).Reject(func(n, _ int) bool { return n%2 == 0 }).All()
	assertSlice(t, got, []int{1, 3, 5})
}

func TestWhere(t *testing.T) {
	got := ints(1, 2, 3).Where(func(n, _ int) bool { return n > 1 }).All()
	assertSlice(t, got, []int{2, 3})
}

func TestWhereNot(t *testing.T) {
	got := ints(1, 2, 3).WhereNot(func(n, _ int) bool { return n > 1 }).All()
	assertSlice(t, got, []int{1})
}

func TestMapAny(t *testing.T) {
	got := ints(1, 2, 3).Map(func(n, _ int) any { return n * 2 }).All()
	if len(got) != 3 || got[1] != 4 {
		t.Fatalf("Map = %v", got)
	}
}

func TestFlatMapAny(t *testing.T) {
	got := ints(1, 2, 3).FlatMap(func(n, _ int) []any { return []any{n, n * 10} }).All()
	if len(got) != 6 {
		t.Fatalf("FlatMap len = %d; want 6", len(got))
	}
}

func TestPluckAny(t *testing.T) {
	got := ints(1, 2, 3).Pluck(func(n int) any { return n * n }).All()
	if len(got) != 3 || got[0] != 1 || got[1] != 4 || got[2] != 9 {
		t.Fatalf("Pluck = %v", got)
	}
}

func TestReduceSameType(t *testing.T) {
	sum := ints(1, 2, 3, 4, 5).Reduce(func(carry, n int) int { return carry + n }, 0)
	if sum != 15 {
		t.Fatalf("Reduce sum = %d; want 15", sum)
	}
}

func TestUnique(t *testing.T) {
	got := ints(1, 2, 2, 3, 3, 3).Unique(nil).All()
	assertSlice(t, got, []int{1, 2, 3})
}

func TestUniqueWithFn(t *testing.T) {
	// Key by string length — "apple" and "APPLE" both have length 5.
	c := collections.New("hi", "apple", "APPLE", "banana")
	got := c.Unique(func(s string) any { return len(s) }).All()
	// lengths: 2, 5, 5, 6 → 3 unique
	if len(got) != 3 {
		t.Fatalf("Unique with fn = %v; want 3 items", got)
	}
}

func TestDiff(t *testing.T) {
	a := ints(1, 2, 3, 4, 5)
	b := ints(2, 4)
	key := func(n int) any { return n }
	got := a.Diff(b, key).All()
	assertSlice(t, got, []int{1, 3, 5})
}

func TestIntersect(t *testing.T) {
	a := ints(1, 2, 3, 4, 5)
	b := ints(2, 4, 6)
	key := func(n int) any { return n }
	got := a.Intersect(b, key).All()
	assertSlice(t, got, []int{2, 4})
}

func TestReverse(t *testing.T) {
	got := ints(1, 2, 3).Reverse().All()
	assertSlice(t, got, []int{3, 2, 1})
}

func TestSort(t *testing.T) {
	got := ints(3, 1, 4, 1, 5).Sort(func(a, b int) bool { return a < b }).All()
	assertSlice(t, got, []int{1, 1, 3, 4, 5})
}

func TestSortBy(t *testing.T) {
	got := ints(5, 3, 1, 4, 2).SortBy(func(n int) float64 { return float64(n) }).All()
	assertSlice(t, got, []int{1, 2, 3, 4, 5})
}

func TestSortByDesc(t *testing.T) {
	got := ints(5, 3, 1, 4, 2).SortByDesc(func(n int) float64 { return float64(n) }).All()
	assertSlice(t, got, []int{5, 4, 3, 2, 1})
}

func TestShuffle(t *testing.T) {
	orig := ints(1, 2, 3, 4, 5)
	shuffled := orig.Shuffle()
	// The original must be unchanged
	assertSlice(t, orig.All(), []int{1, 2, 3, 4, 5})
	// The shuffled must have the same length
	if shuffled.Count() != 5 {
		t.Fatal("Shuffle changed count")
	}
}

func TestRandom(t *testing.T) {
	c := ints(1, 2, 3, 4, 5)
	r := c.Random(3)
	if r.Count() != 3 {
		t.Fatalf("Random count = %d; want 3", r.Count())
	}
	// Random(n >= Count()) returns all
	r2 := c.Random(10)
	if r2.Count() != 5 {
		t.Fatalf("Random(>=count) = %d; want 5", r2.Count())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Add / Remove
// ─────────────────────────────────────────────────────────────────────────────

func TestPush(t *testing.T) {
	orig := ints(1, 2)
	c := orig.Push(3, 4)
	assertSlice(t, c.All(), []int{1, 2, 3, 4})
	assertSlice(t, orig.All(), []int{1, 2}) // immutable
}

func TestPrepend(t *testing.T) {
	got := ints(3, 4).Prepend(1, 2).All()
	assertSlice(t, got, []int{1, 2, 3, 4})
}

func TestPop(t *testing.T) {
	v, rest, ok := ints(1, 2, 3).Pop()
	if !ok || v != 3 {
		t.Fatalf("Pop = %v, ok=%v; want 3", v, ok)
	}
	assertSlice(t, rest.All(), []int{1, 2})

	_, _, ok = collections.Empty[int]().Pop()
	if ok {
		t.Fatal("Pop on empty should return false")
	}
}

func TestShift(t *testing.T) {
	v, rest, ok := ints(1, 2, 3).Shift()
	if !ok || v != 1 {
		t.Fatalf("Shift = %v, ok=%v; want 1", v, ok)
	}
	assertSlice(t, rest.All(), []int{2, 3})
}

func TestPull(t *testing.T) {
	v, rest, ok := ints(10, 20, 30).Pull(1)
	if !ok || v != 20 {
		t.Fatalf("Pull(1) = %v, ok=%v; want 20", v, ok)
	}
	assertSlice(t, rest.All(), []int{10, 30})

	_, _, ok = ints(1).Pull(5)
	if ok {
		t.Fatal("Pull out of range should return false")
	}
}

func TestForget(t *testing.T) {
	got := ints(1, 2, 3).Forget(1).All()
	assertSlice(t, got, []int{1, 3})

	// Out of range — unchanged
	orig := ints(1, 2)
	assertSlice(t, orig.Forget(99).All(), []int{1, 2})
}

func TestConcat(t *testing.T) {
	got := ints(1, 2).Concat(ints(3, 4)).All()
	assertSlice(t, got, []int{1, 2, 3, 4})
}

func TestMerge(t *testing.T) {
	got := ints(1, 2).Merge(ints(3, 4)).All()
	assertSlice(t, got, []int{1, 2, 3, 4})
}

// ─────────────────────────────────────────────────────────────────────────────
// Slicing & Pagination
// ─────────────────────────────────────────────────────────────────────────────

func TestTake(t *testing.T) {
	c := ints(1, 2, 3, 4, 5)
	assertSlice(t, c.Take(3).All(), []int{1, 2, 3})
	assertSlice(t, c.Take(0).All(), []int{})
	assertSlice(t, c.Take(10).All(), []int{1, 2, 3, 4, 5})
	assertSlice(t, c.Take(-2).All(), []int{4, 5}) // last 2
}

func TestTakeUntil(t *testing.T) {
	got := ints(1, 2, 3, 4, 5).TakeUntil(func(n int) bool { return n >= 3 }).All()
	assertSlice(t, got, []int{1, 2})
}

func TestTakeWhile(t *testing.T) {
	got := ints(1, 2, 3, 4, 5).TakeWhile(func(n int) bool { return n < 4 }).All()
	assertSlice(t, got, []int{1, 2, 3})
}

func TestSkip(t *testing.T) {
	c := ints(1, 2, 3, 4, 5)
	assertSlice(t, c.Skip(2).All(), []int{3, 4, 5})
	assertSlice(t, c.Skip(0).All(), []int{1, 2, 3, 4, 5})
	assertSlice(t, c.Skip(10).All(), []int{})
	assertSlice(t, c.Skip(-2).All(), []int{1, 2, 3}) // all but last 2
}

func TestSkipUntil(t *testing.T) {
	got := ints(1, 2, 3, 4).SkipUntil(func(n int) bool { return n >= 3 }).All()
	assertSlice(t, got, []int{3, 4})
}

func TestSkipWhile(t *testing.T) {
	got := ints(1, 2, 3, 4).SkipWhile(func(n int) bool { return n < 3 }).All()
	assertSlice(t, got, []int{3, 4})
}

func TestSlice(t *testing.T) {
	c := ints(1, 2, 3, 4, 5)
	assertSlice(t, c.Slice(1, 3).All(), []int{2, 3, 4})
	assertSlice(t, c.Slice(-3, -1).All(), []int{3, 4, 5}) // negative offset, rest
	assertSlice(t, c.Slice(0, -1).All(), []int{1, 2, 3, 4, 5})
	assertSlice(t, c.Slice(10, 2).All(), []int{})
}

func TestChunk(t *testing.T) {
	c := ints(1, 2, 3, 4, 5)
	chunks := c.Chunk(2)
	if len(chunks) != 3 {
		t.Fatalf("Chunk count = %d; want 3", len(chunks))
	}
	assertSlice(t, chunks[0], []int{1, 2})
	assertSlice(t, chunks[2], []int{5})
}

func TestChunkZeroSize(t *testing.T) {
	if len(ints(1, 2, 3).Chunk(0)) != 0 {
		t.Fatal("Chunk(0) should return empty")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregation
// ─────────────────────────────────────────────────────────────────────────────

func TestSum(t *testing.T) {
	s := ints(1, 2, 3, 4, 5).Sum(func(n int) float64 { return float64(n) })
	if s != 15 {
		t.Fatalf("Sum = %f; want 15", s)
	}
}

func TestAverage(t *testing.T) {
	avg := ints(1, 2, 3, 4, 5).Average(func(n int) float64 { return float64(n) })
	if avg != 3 {
		t.Fatalf("Average = %f; want 3", avg)
	}
	if collections.Empty[int]().Average(func(n int) float64 { return float64(n) }) != 0 {
		t.Fatal("Average of empty should be 0")
	}
}

func TestMin(t *testing.T) {
	v, ok := ints(3, 1, 4, 1, 5).Min(func(n int) float64 { return float64(n) })
	if !ok || v != 1 {
		t.Fatalf("Min = %v, ok=%v; want 1", v, ok)
	}
	_, ok = collections.Empty[int]().Min(func(n int) float64 { return float64(n) })
	if ok {
		t.Fatal("Min on empty should return false")
	}
}

func TestMax(t *testing.T) {
	v, ok := ints(3, 1, 4, 1, 5).Max(func(n int) float64 { return float64(n) })
	if !ok || v != 5 {
		t.Fatalf("Max = %v, ok=%v; want 5", v, ok)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Grouping / Partitioning
// ─────────────────────────────────────────────────────────────────────────────

func TestGroupBy(t *testing.T) {
	groups := ints(1, 2, 3, 4, 5).GroupBy(func(n int) any {
		if n%2 == 0 {
			return "even"
		}
		return "odd"
	})
	if groups["even"].Count() != 2 || groups["odd"].Count() != 3 {
		t.Fatalf("GroupBy failed: %v", groups)
	}
}

func TestKeyBy(t *testing.T) {
	keyed := ints(10, 20, 30).KeyBy(func(n int) any { return fmt.Sprintf("%d", n) })
	if keyed["20"] != 20 {
		t.Fatal("KeyBy failed")
	}
}

func TestPartition(t *testing.T) {
	evens, odds := ints(1, 2, 3, 4, 5).Partition(func(n int) bool { return n%2 == 0 })
	assertSlice(t, evens.All(), []int{2, 4})
	assertSlice(t, odds.All(), []int{1, 3, 5})
}

// ─────────────────────────────────────────────────────────────────────────────
// String helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestImplode(t *testing.T) {
	got := ints(1, 2, 3).Implode(", ", func(n int) string { return fmt.Sprintf("%d", n) })
	if got != "1, 2, 3" {
		t.Fatalf("Implode = %q; want \"1, 2, 3\"", got)
	}
}

func TestFlip(t *testing.T) {
	flip := ints(10, 20, 30).Flip()
	if flip["20"] != 1 {
		t.Fatal("Flip failed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Conditional
// ─────────────────────────────────────────────────────────────────────────────

func TestWhen(t *testing.T) {
	c := ints(1, 2, 3).When(true, func(c *collections.Collection[int]) *collections.Collection[int] {
		return c.Push(4)
	})
	assertSlice(t, c.All(), []int{1, 2, 3, 4})

	c2 := ints(1, 2, 3).When(false, func(c *collections.Collection[int]) *collections.Collection[int] {
		return c.Push(99)
	})
	assertSlice(t, c2.All(), []int{1, 2, 3})
}

func TestUnless(t *testing.T) {
	c := ints(1, 2).Unless(false, func(c *collections.Collection[int]) *collections.Collection[int] {
		return c.Push(3)
	})
	assertSlice(t, c.All(), []int{1, 2, 3})
}

func TestWhenEmpty(t *testing.T) {
	filled := collections.Empty[int]().WhenEmpty(func(c *collections.Collection[int]) *collections.Collection[int] {
		return c.Push(42)
	})
	assertSlice(t, filled.All(), []int{42})

	unchanged := ints(1).WhenEmpty(func(c *collections.Collection[int]) *collections.Collection[int] {
		return c.Push(99)
	})
	assertSlice(t, unchanged.All(), []int{1})
}

func TestWhenNotEmpty(t *testing.T) {
	c := ints(1, 2).WhenNotEmpty(func(c *collections.Collection[int]) *collections.Collection[int] {
		return c.Push(3)
	})
	assertSlice(t, c.All(), []int{1, 2, 3})
}

// ─────────────────────────────────────────────────────────────────────────────
// Immutability
// ─────────────────────────────────────────────────────────────────────────────

func TestImmutability(t *testing.T) {
	orig := ints(1, 2, 3)
	_ = orig.Push(4)
	_ = orig.Prepend(0)
	_ = orig.Filter(func(n, _ int) bool { return n > 1 })
	_ = orig.Reverse()
	assertSlice(t, orig.All(), []int{1, 2, 3}) // unchanged
}
