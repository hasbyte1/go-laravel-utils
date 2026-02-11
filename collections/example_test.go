package collections_test

import (
	"fmt"
	"strconv"

	"github.com/hasbyte1/go-laravel-utils/collections"
)

func ExampleNew() {
	c := collections.New(1, 2, 3, 4, 5)
	fmt.Println(c.Count(), c.Sum(func(n int) float64 { return float64(n) }))
	// Output: 5 15
}

func ExampleCollection_Filter() {
	result := collections.New(1, 2, 3, 4, 5, 6).
		Filter(func(n, _ int) bool { return n%2 == 0 }).
		All()
	fmt.Println(result)
	// Output: [2 4 6]
}

func ExampleCollection_Sort() {
	result := collections.New(5, 3, 1, 4, 2).
		Sort(func(a, b int) bool { return a < b }).
		All()
	fmt.Println(result)
	// Output: [1 2 3 4 5]
}

func ExampleCollection_Partition() {
	evens, odds := collections.New(1, 2, 3, 4, 5).
		Partition(func(n int) bool { return n%2 == 0 })
	fmt.Println(evens.All(), odds.All())
	// Output: [2 4] [1 3 5]
}

func ExampleCollection_Chunk() {
	for _, chunk := range collections.New(1, 2, 3, 4, 5).Chunk(2) {
		fmt.Println(chunk)
	}
	// Output:
	// [1 2]
	// [3 4]
	// [5]
}

func ExampleCollection_Implode() {
	s := collections.New(1, 2, 3).Implode(", ", strconv.Itoa)
	fmt.Println(s)
	// Output: 1, 2, 3
}

func ExampleMap() {
	result := collections.Map(
		collections.New(1, 2, 3),
		func(n, _ int) string { return strconv.Itoa(n * n) },
	)
	fmt.Println(result.Implode(", ", func(s string) string { return s }))
	// Output: 1, 4, 9
}

func ExampleReduce() {
	sum := collections.Reduce(
		collections.New(1, 2, 3, 4, 5),
		func(acc, n, _ int) int { return acc + n },
		0,
	)
	fmt.Println(sum)
	// Output: 15
}

func ExampleZip() {
	keys := collections.New("a", "b", "c")
	vals := collections.New(1, 2, 3)
	pairs := collections.Zip(keys, vals)
	pairs.Each(func(p collections.Pair[string, int], _ int) {
		fmt.Printf("%s=%d\n", p.First, p.Second)
	})
	// Output:
	// a=1
	// b=2
	// c=3
}

func ExampleCollapse() {
	nested := collections.New([]int{1, 2}, []int{3, 4}, []int{5})
	flat := collections.Collapse(nested)
	fmt.Println(flat.All())
	// Output: [1 2 3 4 5]
}

func ExampleGroupBy() {
	groups := collections.GroupBy(
		collections.New(1, 2, 3, 4, 5, 6),
		func(n int) string {
			if n%2 == 0 {
				return "even"
			}
			return "odd"
		},
	)
	fmt.Println(groups["even"].Sum(func(n int) float64 { return float64(n) }))
	// Output: 12
}

func ExampleCollection_When() {
	result := collections.New(1, 2, 3).
		When(true, func(c *collections.Collection[int]) *collections.Collection[int] {
			return c.Push(4)
		}).
		Count()
	fmt.Println(result)
	// Output: 4
}
