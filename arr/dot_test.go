package arr_test

import (
	"testing"

	"github.com/hasbyte1/go-laravel-utils/arr"
)

func makeNested() map[string]any {
	return map[string]any{
		"user": map[string]any{
			"name": "Alice",
			"address": map[string]any{
				"city":    "London",
				"country": "UK",
			},
		},
		"score": 42,
	}
}

func TestDot(t *testing.T) {
	flat := arr.Dot(makeNested())
	if flat["user.name"] != "Alice" {
		t.Fatalf("Dot user.name = %v; want Alice", flat["user.name"])
	}
	if flat["user.address.city"] != "London" {
		t.Fatalf("Dot user.address.city = %v; want London", flat["user.address.city"])
	}
	if flat["score"] != 42 {
		t.Fatalf("Dot score = %v; want 42", flat["score"])
	}
}

func TestUndot(t *testing.T) {
	flat := map[string]any{
		"a.b":   1,
		"a.c":   2,
		"d":     3,
		"e.f.g": 4,
	}
	nested := arr.Undot(flat)
	aMap, ok := nested["a"].(map[string]any)
	if !ok || aMap["b"] != 1 || aMap["c"] != 2 {
		t.Fatalf("Undot a = %v", nested["a"])
	}
	if nested["d"] != 3 {
		t.Fatal("Undot d failed")
	}
}

func TestGet(t *testing.T) {
	m := makeNested()
	if v := arr.Get(m, "user.name"); v != "Alice" {
		t.Fatalf("Get user.name = %v; want Alice", v)
	}
	if v := arr.Get(m, "user.address.city"); v != "London" {
		t.Fatalf("Get city = %v; want London", v)
	}
	if v := arr.Get(m, "score"); v != 42 {
		t.Fatalf("Get score = %v; want 42", v)
	}
	if v := arr.Get(m, "missing"); v != nil {
		t.Fatalf("Get missing = %v; want nil", v)
	}
	if v := arr.Get(m, "missing", "default"); v != "default" {
		t.Fatalf("Get missing default = %v; want default", v)
	}
}

func TestSet(t *testing.T) {
	m := map[string]any{}
	arr.Set(m, "a.b.c", 42)
	got := arr.Get(m, "a.b.c")
	if got != 42 {
		t.Fatalf("Set/Get a.b.c = %v; want 42", got)
	}
}

func TestSetOverwritesExisting(t *testing.T) {
	m := makeNested()
	arr.Set(m, "user.name", "Bob")
	if arr.Get(m, "user.name") != "Bob" {
		t.Fatal("Set did not overwrite")
	}
}

func TestHas(t *testing.T) {
	m := makeNested()
	if !arr.Has(m, "user.name") {
		t.Fatal("Has user.name should be true")
	}
	if !arr.Has(m, "user.address.city") {
		t.Fatal("Has user.address.city should be true")
	}
	if arr.Has(m, "user.missing") {
		t.Fatal("Has user.missing should be false")
	}
	if arr.Has(m, "user.name.deep") {
		t.Fatal("Has beyond scalar should be false")
	}
}

func TestHasAll(t *testing.T) {
	m := makeNested()
	if !arr.HasAll(m, "user.name", "score") {
		t.Fatal("HasAll should return true")
	}
	if arr.HasAll(m, "user.name", "missing") {
		t.Fatal("HasAll should return false when one key missing")
	}
}

func TestHasAny(t *testing.T) {
	m := makeNested()
	if !arr.HasAny(m, "missing", "score") {
		t.Fatal("HasAny should be true")
	}
	if arr.HasAny(m, "x", "y") {
		t.Fatal("HasAny should be false")
	}
}

func TestForget(t *testing.T) {
	m := makeNested()
	arr.Forget(m, "user.address.city")
	if arr.Has(m, "user.address.city") {
		t.Fatal("Forget did not remove key")
	}
	if !arr.Has(m, "user.address.country") {
		t.Fatal("Forget removed sibling key")
	}
}

func TestForgetTopLevel(t *testing.T) {
	m := map[string]any{"a": 1, "b": 2}
	arr.Forget(m, "a")
	if arr.Has(m, "a") {
		t.Fatal("Forget top-level failed")
	}
	if !arr.Has(m, "b") {
		t.Fatal("Forget removed wrong key")
	}
}

func TestOnly(t *testing.T) {
	m := map[string]any{"a": 1, "b": 2, "c": 3}
	got := arr.Only(m, "a", "c")
	if len(got) != 2 || got["a"] != 1 || got["c"] != 3 {
		t.Fatalf("Only = %v", got)
	}
	if _, ok := got["b"]; ok {
		t.Fatal("Only should not include b")
	}
}

func TestExcept(t *testing.T) {
	m := map[string]any{"a": 1, "b": 2, "c": 3}
	got := arr.Except(m, "b")
	if len(got) != 2 || got["a"] != 1 || got["c"] != 3 {
		t.Fatalf("Except = %v", got)
	}
	if _, ok := got["b"]; ok {
		t.Fatal("Except should not include b")
	}
}

func TestMerge(t *testing.T) {
	dst := map[string]any{
		"a": 1,
		"nested": map[string]any{"x": 10},
	}
	src := map[string]any{
		"b": 2,
		"nested": map[string]any{"y": 20},
	}
	arr.Merge(dst, src)
	if dst["b"] != 2 {
		t.Fatal("Merge did not add b")
	}
	nested, _ := dst["nested"].(map[string]any)
	if nested["x"] != 10 || nested["y"] != 20 {
		t.Fatalf("Merge nested = %v; want x=10, y=20", nested)
	}
}

func TestMergeOverwrite(t *testing.T) {
	dst := map[string]any{"a": 1}
	src := map[string]any{"a": 99}
	arr.Merge(dst, src)
	if dst["a"] != 99 {
		t.Fatal("Merge should overwrite scalar values")
	}
}
