package arr_test

import (
	"testing"

	"github.com/hasbyte1/go-laravel-utils/arr"
)

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

// ─── First / Last ─────────────────────────────────────────────────────────────

func TestFirst(t *testing.T) {
	v, ok := arr.First([]int{10, 20, 30})
	if !ok || v != 10 {
		t.Fatalf("First = %v, %v; want 10, true", v, ok)
	}
	_, ok = arr.First([]int{})
	if ok {
		t.Fatal("First on empty should return false")
	}
}

func TestFirstWithPredicate(t *testing.T) {
	v, ok := arr.First([]int{1, 2, 3, 4}, func(n int) bool { return n > 2 })
	if !ok || v != 3 {
		t.Fatalf("First predicate = %v, %v; want 3, true", v, ok)
	}
}

func TestLast(t *testing.T) {
	v, ok := arr.Last([]int{10, 20, 30})
	if !ok || v != 30 {
		t.Fatalf("Last = %v, %v; want 30, true", v, ok)
	}
}

func TestLastWithPredicate(t *testing.T) {
	v, ok := arr.Last([]int{1, 2, 3, 4}, func(n int) bool { return n < 3 })
	if !ok || v != 2 {
		t.Fatalf("Last predicate = %v, %v; want 2, true", v, ok)
	}
}

// ─── Contains / Index ─────────────────────────────────────────────────────────

func TestContains(t *testing.T) {
	if !arr.Contains([]int{1, 2, 3}, func(n int) bool { return n == 2 }) {
		t.Fatal("Contains should be true")
	}
	if arr.Contains([]int{1, 2, 3}, func(n int) bool { return n == 99 }) {
		t.Fatal("Contains should be false")
	}
}

func TestContainsValue(t *testing.T) {
	if !arr.ContainsValue([]string{"a", "b", "c"}, "b") {
		t.Fatal("ContainsValue should be true")
	}
	if arr.ContainsValue([]string{"a", "b"}, "z") {
		t.Fatal("ContainsValue should be false")
	}
}

func TestIndexOf(t *testing.T) {
	if i := arr.IndexOf([]int{10, 20, 30}, 20); i != 1 {
		t.Fatalf("IndexOf = %d; want 1", i)
	}
	if i := arr.IndexOf([]int{10, 20}, 99); i != -1 {
		t.Fatalf("IndexOf missing = %d; want -1", i)
	}
}

func TestSearch(t *testing.T) {
	if i := arr.Search([]int{1, 2, 3}, func(n int) bool { return n == 3 }); i != 2 {
		t.Fatalf("Search = %d; want 2", i)
	}
}

// ─── Transformation ───────────────────────────────────────────────────────────

func TestMap(t *testing.T) {
	got := arr.Map([]int{1, 2, 3}, func(n, _ int) int { return n * 2 })
	assertSlice(t, got, []int{2, 4, 6})
}

func TestFilter(t *testing.T) {
	got := arr.Filter([]int{1, 2, 3, 4, 5}, func(n, _ int) bool { return n%2 == 0 })
	assertSlice(t, got, []int{2, 4})
}

func TestReject(t *testing.T) {
	got := arr.Reject([]int{1, 2, 3, 4, 5}, func(n, _ int) bool { return n%2 == 0 })
	assertSlice(t, got, []int{1, 3, 5})
}

func TestReduce(t *testing.T) {
	sum := arr.Reduce([]int{1, 2, 3, 4, 5}, func(acc, n, _ int) int { return acc + n }, 0)
	if sum != 15 {
		t.Fatalf("Reduce = %d; want 15", sum)
	}
}

func TestFlatMap(t *testing.T) {
	got := arr.FlatMap([]int{1, 2, 3}, func(n, _ int) []int { return []int{n, n * 10} })
	assertSlice(t, got, []int{1, 10, 2, 20, 3, 30})
}

func TestPluck(t *testing.T) {
	type P struct{ Name string }
	names := arr.Pluck([]P{{"Alice"}, {"Bob"}}, func(p P) string { return p.Name })
	assertSlice(t, names, []string{"Alice", "Bob"})
}

// ─── Set operations ───────────────────────────────────────────────────────────

func TestUnique(t *testing.T) {
	got := arr.Unique([]int{1, 2, 2, 3, 3, 3})
	assertSlice(t, got, []int{1, 2, 3})
}

func TestUniqueBy(t *testing.T) {
	type P struct{ ID, Val int }
	items := []P{{1, 10}, {2, 20}, {1, 99}}
	got := arr.UniqueBy(items, func(p P) int { return p.ID })
	if len(got) != 2 {
		t.Fatalf("UniqueBy = %v; want 2 items", got)
	}
}

func TestDiff(t *testing.T) {
	got := arr.Diff([]int{1, 2, 3, 4, 5}, []int{2, 4})
	assertSlice(t, got, []int{1, 3, 5})
}

func TestIntersect(t *testing.T) {
	got := arr.Intersect([]int{1, 2, 3, 4}, []int{2, 4, 6})
	assertSlice(t, got, []int{2, 4})
}

// ─── Restructuring ────────────────────────────────────────────────────────────

func TestChunk(t *testing.T) {
	chunks := arr.Chunk([]int{1, 2, 3, 4, 5}, 2)
	if len(chunks) != 3 {
		t.Fatalf("Chunk len = %d; want 3", len(chunks))
	}
	assertSlice(t, chunks[0], []int{1, 2})
	assertSlice(t, chunks[2], []int{5})
}

func TestChunkEmptyOrZero(t *testing.T) {
	if len(arr.Chunk([]int{}, 2)) != 0 {
		t.Fatal("Chunk empty should return empty")
	}
	if len(arr.Chunk([]int{1}, 0)) != 0 {
		t.Fatal("Chunk size 0 should return empty")
	}
}

func TestCollapse(t *testing.T) {
	got := arr.Collapse([][]int{{1, 2}, {3, 4}, {5}})
	assertSlice(t, got, []int{1, 2, 3, 4, 5})
}

func TestFlatten(t *testing.T) {
	got := arr.Flatten([]any{1, []any{2, 3}, []any{4, []any{5}}})
	if len(got) != 5 {
		t.Fatalf("Flatten len = %d; want 5", len(got))
	}
}

func TestReverse(t *testing.T) {
	got := arr.Reverse([]int{1, 2, 3})
	assertSlice(t, got, []int{3, 2, 1})
}

func TestPrepend(t *testing.T) {
	got := arr.Prepend([]int{3, 4}, 1, 2)
	assertSlice(t, got, []int{1, 2, 3, 4})
}

func TestWrap(t *testing.T) {
	got := arr.Wrap(42)
	assertSlice(t, got, []int{42})
}

func TestPartition(t *testing.T) {
	pass, fail := arr.Partition([]int{1, 2, 3, 4, 5}, func(n int) bool { return n%2 == 0 })
	assertSlice(t, pass, []int{2, 4})
	assertSlice(t, fail, []int{1, 3, 5})
}

func TestZip(t *testing.T) {
	pairs := arr.Zip([]string{"a", "b"}, []int{1, 2})
	if len(pairs) != 2 || pairs[0].First != "a" || pairs[0].Second != 1 {
		t.Fatalf("Zip = %v", pairs)
	}
}

func TestZipUnequal(t *testing.T) {
	pairs := arr.Zip([]int{1, 2, 3}, []int{10, 20})
	if len(pairs) != 2 {
		t.Fatalf("Zip unequal len = %d; want 2", len(pairs))
	}
}

func TestCombine(t *testing.T) {
	m, err := arr.Combine([]string{"x", "y"}, []int{10, 20})
	if err != nil || m["y"] != 20 {
		t.Fatalf("Combine failed: %v %v", m, err)
	}
	_, err = arr.Combine([]string{"a"}, []int{1, 2})
	if err == nil {
		t.Fatal("Combine mismatch should error")
	}
}

func TestGroupBy(t *testing.T) {
	groups := arr.GroupBy([]int{1, 2, 3, 4}, func(n int) string {
		if n%2 == 0 {
			return "even"
		}
		return "odd"
	})
	assertSlice(t, groups["even"], []int{2, 4})
	assertSlice(t, groups["odd"], []int{1, 3})
}

func TestKeyBy(t *testing.T) {
	type Item struct{ ID int }
	keyed := arr.KeyBy([]Item{{1}, {2}, {3}}, func(i Item) int { return i.ID })
	if keyed[2].ID != 2 {
		t.Fatal("KeyBy failed")
	}
}

// ─── Sorting ──────────────────────────────────────────────────────────────────

func TestSort(t *testing.T) {
	got := arr.Sort([]int{3, 1, 4, 1, 5}, func(a, b int) bool { return a < b })
	assertSlice(t, got, []int{1, 1, 3, 4, 5})
}

func TestShuffle(t *testing.T) {
	orig := []int{1, 2, 3, 4, 5}
	got := arr.Shuffle(orig)
	if len(got) != 5 {
		t.Fatal("Shuffle changed length")
	}
	// Ensure original is unchanged
	assertSlice(t, orig, []int{1, 2, 3, 4, 5})
}

func TestRandom(t *testing.T) {
	got := arr.Random([]int{1, 2, 3, 4, 5}, 3)
	if len(got) != 3 {
		t.Fatalf("Random len = %d; want 3", len(got))
	}
}

// ─── Aggregation ──────────────────────────────────────────────────────────────

func TestSum(t *testing.T) {
	s := arr.Sum([]int{1, 2, 3, 4, 5}, func(n int) float64 { return float64(n) })
	if s != 15 {
		t.Fatalf("Sum = %f; want 15", s)
	}
}

func TestMin(t *testing.T) {
	v, ok := arr.Min([]int{3, 1, 4, 1, 5}, func(n int) float64 { return float64(n) })
	if !ok || v != 1 {
		t.Fatalf("Min = %v, %v; want 1, true", v, ok)
	}
	_, ok = arr.Min([]int{}, func(n int) float64 { return float64(n) })
	if ok {
		t.Fatal("Min on empty should return false")
	}
}

func TestMax(t *testing.T) {
	v, ok := arr.Max([]int{3, 1, 4, 1, 5}, func(n int) float64 { return float64(n) })
	if !ok || v != 5 {
		t.Fatalf("Max = %v, %v; want 5, true", v, ok)
	}
}
