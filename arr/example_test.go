package arr_test

import (
	"fmt"

	"github.com/hasbyte1/go-laravel-utils/arr"
)

func ExampleFilter() {
	evens := arr.Filter([]int{1, 2, 3, 4, 5}, func(n, _ int) bool { return n%2 == 0 })
	fmt.Println(evens)
	// Output: [2 4]
}

func ExampleMap() {
	doubled := arr.Map([]int{1, 2, 3}, func(n, _ int) int { return n * 2 })
	fmt.Println(doubled)
	// Output: [2 4 6]
}

func ExampleChunk() {
	for _, c := range arr.Chunk([]int{1, 2, 3, 4, 5}, 2) {
		fmt.Println(c)
	}
	// Output:
	// [1 2]
	// [3 4]
	// [5]
}

func ExampleCollapse() {
	flat := arr.Collapse([][]int{{1, 2}, {3, 4}, {5}})
	fmt.Println(flat)
	// Output: [1 2 3 4 5]
}

func ExampleGroupBy() {
	groups := arr.GroupBy([]int{1, 2, 3, 4}, func(n int) string {
		if n%2 == 0 {
			return "even"
		}
		return "odd"
	})
	fmt.Println(groups["even"])
	// Output: [2 4]
}

func ExampleDot() {
	m := map[string]any{
		"db": map[string]any{
			"host": "localhost",
			"port": 5432,
		},
	}
	flat := arr.Dot(m)
	fmt.Println(flat["db.host"])
	// Output: localhost
}

func ExampleGet() {
	m := map[string]any{
		"user": map[string]any{
			"address": map[string]any{"city": "London"},
		},
	}
	fmt.Println(arr.Get(m, "user.address.city"))
	// Output: London
}

func ExampleSet() {
	m := map[string]any{}
	arr.Set(m, "config.debug", true)
	fmt.Println(arr.Get(m, "config.debug"))
	// Output: true
}
