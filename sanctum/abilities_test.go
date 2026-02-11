package sanctum

import "testing"

func TestCan(t *testing.T) {
	tests := []struct {
		abilities []string
		ability   string
		want      bool
	}{
		{[]string{"read", "write"}, "read", true},
		{[]string{"read", "write"}, "delete", false},
		{[]string{"*"}, "anything", true},
		{[]string{"*"}, "read", true},
		{[]string{}, "read", false},
		{nil, "read", false},
	}
	for _, tc := range tests {
		got := Can(tc.abilities, tc.ability)
		if got != tc.want {
			t.Errorf("Can(%v, %q) = %v, want %v", tc.abilities, tc.ability, got, tc.want)
		}
	}
}

func TestCanAll(t *testing.T) {
	tests := []struct {
		abilities []string
		required  []string
		want      bool
	}{
		{[]string{"read", "write"}, []string{"read", "write"}, true},
		{[]string{"read", "write"}, []string{"read"}, true},
		{[]string{"read"}, []string{"read", "write"}, false},
		{[]string{"*"}, []string{"read", "write", "delete"}, true},
		{[]string{"read"}, []string{}, true}, // empty required → always true
		{nil, []string{}, true},
		{nil, []string{"read"}, false},
	}
	for _, tc := range tests {
		got := CanAll(tc.abilities, tc.required)
		if got != tc.want {
			t.Errorf("CanAll(%v, %v) = %v, want %v", tc.abilities, tc.required, got, tc.want)
		}
	}
}

func TestCanAny(t *testing.T) {
	tests := []struct {
		abilities []string
		required  []string
		want      bool
	}{
		{[]string{"read", "write"}, []string{"delete", "write"}, true},
		{[]string{"read"}, []string{"write", "delete"}, false},
		{[]string{"*"}, []string{"anything"}, true},
		{[]string{"read"}, []string{}, false}, // empty required → false
		{nil, []string{"read"}, false},
	}
	for _, tc := range tests {
		got := CanAny(tc.abilities, tc.required)
		if got != tc.want {
			t.Errorf("CanAny(%v, %v) = %v, want %v", tc.abilities, tc.required, got, tc.want)
		}
	}
}

func TestHasWildcard(t *testing.T) {
	if !HasWildcard([]string{"*"}) {
		t.Error("expected true for [*]")
	}
	if !HasWildcard([]string{"read", "*", "write"}) {
		t.Error("expected true when * is present among other abilities")
	}
	if HasWildcard([]string{"read", "write"}) {
		t.Error("expected false when no * is present")
	}
	if HasWildcard(nil) {
		t.Error("expected false for nil")
	}
	if HasWildcard([]string{}) {
		t.Error("expected false for empty")
	}
}
