package collections_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hasbyte1/go-laravel-utils/collections"
)

func TestMapFunc(t *testing.T) {
	got := collections.Map(ints(1, 2, 3), func(n, _ int) string {
		return strconv.Itoa(n * 2)
	}).All()
	if len(got) != 3 || got[0] != "2" || got[1] != "4" || got[2] != "6" {
		t.Fatalf("Map = %v", got)
	}
}

func TestFlatMapFunc(t *testing.T) {
	got := collections.FlatMap(ints(1, 2, 3), func(n, _ int) []string {
		return []string{strconv.Itoa(n), strconv.Itoa(n * 10)}
	}).All()
	want := []string{"1", "10", "2", "20", "3", "30"}
	if len(got) != len(want) {
		t.Fatalf("FlatMap len = %d; want %d: %v", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("FlatMap[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestReduceFunc(t *testing.T) {
	// int → string
	s := collections.Reduce(ints(1, 2, 3), func(acc string, n, _ int) string {
		if acc == "" {
			return strconv.Itoa(n)
		}
		return acc + "," + strconv.Itoa(n)
	}, "")
	if s != "1,2,3" {
		t.Fatalf("Reduce = %q; want \"1,2,3\"", s)
	}
}

func TestPluckFunc(t *testing.T) {
	type Person struct{ Name string }
	people := collections.New(Person{"Alice"}, Person{"Bob"}, Person{"Carol"})
	names := collections.Pluck(people, func(p Person) string { return p.Name }).All()
	if len(names) != 3 || names[0] != "Alice" {
		t.Fatalf("Pluck = %v", names)
	}
}

func TestGroupByFunc(t *testing.T) {
	groups := collections.GroupBy(ints(1, 2, 3, 4), func(n int) string {
		if n%2 == 0 {
			return "even"
		}
		return "odd"
	})
	if groups["even"].Count() != 2 || groups["odd"].Count() != 2 {
		t.Fatalf("GroupBy = %v", groups)
	}
}

func TestKeyByFunc(t *testing.T) {
	type Item struct{ ID int }
	items := collections.New(Item{1}, Item{2}, Item{3})
	keyed := collections.KeyBy(items, func(item Item) int { return item.ID })
	if keyed[2].ID != 2 {
		t.Fatal("KeyBy failed")
	}
}

func TestZipFunc(t *testing.T) {
	a := collections.New("x", "y", "z")
	b := ints(1, 2, 3)
	pairs := collections.Zip(a, b).All()
	if len(pairs) != 3 {
		t.Fatalf("Zip len = %d; want 3", len(pairs))
	}
	if pairs[0].First != "x" || pairs[0].Second != 1 {
		t.Fatalf("Zip[0] = %v; want (x,1)", pairs[0])
	}
}

func TestZipUnequalLengths(t *testing.T) {
	a := collections.New("a", "b", "c")
	b := ints(1, 2)
	pairs := collections.Zip(a, b)
	if pairs.Count() != 2 {
		t.Fatalf("Zip unequal len = %d; want 2", pairs.Count())
	}
}

func TestCombineFunc(t *testing.T) {
	m, err := collections.Combine([]string{"a", "b", "c"}, []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if m["b"] != 2 {
		t.Fatal("Combine failed")
	}

	_, err = collections.Combine([]string{"a"}, []int{1, 2})
	if err == nil {
		t.Fatal("Combine with mismatched lengths should error")
	}
}

func TestCollapseFunc(t *testing.T) {
	nested := collections.New([]int{1, 2}, []int{3, 4}, []int{5})
	flat := collections.Collapse(nested).All()
	assertSlice(t, flat, []int{1, 2, 3, 4, 5})
}

func TestFlattenFunc(t *testing.T) {
	nested := collections.New([]int{1, 2}, []int{3, 4})
	flat := collections.Flatten(nested).All()
	assertSlice(t, flat, []int{1, 2, 3, 4})
}

func TestFlattenDeepFunc(t *testing.T) {
	inner := collections.New[any](3, 4)
	c := collections.New[any](1, 2, inner, []any{5, 6})
	got := collections.FlattenDeep(c).All()
	if len(got) != 6 {
		t.Fatalf("FlattenDeep len = %d; want 6: %v", len(got), got)
	}
}

func TestMacro(t *testing.T) {
	defer collections.FlushMacros()

	collections.RegisterMacro("sumInts", func(col any, _ ...any) any {
		c := col.(*collections.Collection[int])
		return c.Sum(func(n int) float64 { return float64(n) })
	})

	if !collections.HasMacro("sumInts") {
		t.Fatal("HasMacro should return true")
	}

	result, err := ints(1, 2, 3, 4, 5).Macro("sumInts")
	if err != nil {
		t.Fatal(err)
	}
	if result.(float64) != 15 {
		t.Fatalf("Macro result = %v; want 15", result)
	}
}

func TestMacroNotFound(t *testing.T) {
	_, err := ints(1).Macro("nonexistent_macro_xyz")
	if err == nil {
		t.Fatal("expected ErrMacroNotFound")
	}
}

func TestPairString(t *testing.T) {
	p := collections.Pair[string, int]{First: "hello", Second: 42}
	got := fmt.Sprint(p)
	want := "(hello, 42)"
	if got != want {
		t.Fatalf("Pair.String() = %q; want %q", got, want)
	}
}
