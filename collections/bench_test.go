package collections_test

import (
	"testing"

	"github.com/hasbyte1/go-laravel-utils/collections"
)

// makeInts creates a Collection[int] of size n for benchmarks.
func makeInts(n int) *collections.Collection[int] {
	items := make([]int, n)
	for i := range items {
		items[i] = i + 1
	}
	return collections.From(items)
}

func BenchmarkFilter(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Filter(func(n, _ int) bool { return n%2 == 0 })
	}
}

func BenchmarkMapFunc(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collections.Map(c, func(n, _ int) int { return n * 2 })
	}
}

func BenchmarkReduceFunc(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collections.Reduce(c, func(acc, n, _ int) int { return acc + n }, 0)
	}
}

func BenchmarkSort(b *testing.B) {
	c := makeInts(10_000).Shuffle() // pre-shuffle once
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Sort(func(a, b int) bool { return a < b })
	}
}

func BenchmarkGroupBy(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collections.GroupBy(c, func(n int) string {
			if n%2 == 0 {
				return "even"
			}
			return "odd"
		})
	}
}

func BenchmarkShuffle(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Shuffle()
	}
}

func BenchmarkUnique(b *testing.B) {
	// 50% duplicates
	items := make([]int, 10_000)
	for i := range items {
		items[i] = i % 5000
	}
	c := collections.From(items)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Unique(nil)
	}
}

func BenchmarkChunk(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Chunk(100)
	}
}

func BenchmarkSum(b *testing.B) {
	c := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Sum(func(n int) float64 { return float64(n) })
	}
}

func BenchmarkZip(b *testing.B) {
	a := makeInts(10_000)
	bInts := makeInts(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collections.Zip(a, bInts)
	}
}
