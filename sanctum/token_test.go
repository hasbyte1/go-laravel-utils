package sanctum

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateToken_Format(t *testing.T) {
	result, err := generateToken("user1", "My App", []string{"read"}, nil)
	if err != nil {
		t.Fatalf("generateToken error: %v", err)
	}

	parts := strings.SplitN(result.PlainText, "|", 2)
	if len(parts) != 2 {
		t.Fatalf("expected format id|secret, got %q", result.PlainText)
	}
	if parts[0] == "" || parts[1] == "" {
		t.Fatal("id and secret must be non-empty")
	}
	if result.Token.ID != parts[0] {
		t.Errorf("token.ID = %q, want %q", result.Token.ID, parts[0])
	}
}

func TestGenerateToken_HashMatchesSecret(t *testing.T) {
	result, err := generateToken("u1", "test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _ := parseTokenID(result.PlainText)
	want := HashToken(secret)
	if result.Token.Hash != want {
		t.Errorf("hash mismatch: got %q, want %q", result.Token.Hash, want)
	}
}

func TestGenerateToken_SetsFields(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	result, err := generateToken("u42", "tok", []string{"a", "b"}, &exp)
	if err != nil {
		t.Fatal(err)
	}
	tok := result.Token
	if tok.UserID != "u42" {
		t.Errorf("UserID = %q", tok.UserID)
	}
	if tok.Name != "tok" {
		t.Errorf("Name = %q", tok.Name)
	}
	if len(tok.Abilities) != 2 || tok.Abilities[0] != "a" || tok.Abilities[1] != "b" {
		t.Errorf("Abilities = %v", tok.Abilities)
	}
	if tok.ExpiresAt == nil || !tok.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v", tok.ExpiresAt)
	}
	if tok.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestGenerateToken_AbilitiesIsolated(t *testing.T) {
	abs := []string{"read", "write"}
	result, _ := generateToken("u1", "t", abs, nil)
	abs[0] = "mutated"
	if result.Token.Abilities[0] == "mutated" {
		t.Error("generateToken should copy abilities, not reference the original slice")
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		r, err := generateToken("u", "n", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[r.PlainText] {
			t.Fatal("duplicate plain-text token")
		}
		seen[r.PlainText] = true
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	h1 := HashToken("secret123")
	h2 := HashToken("secret123")
	if h1 != h2 {
		t.Error("HashToken should be deterministic")
	}
}

func TestHashToken_DifferentInputs(t *testing.T) {
	if HashToken("a") == HashToken("b") {
		t.Error("different inputs should produce different hashes")
	}
}

func TestHashToken_IsHex(t *testing.T) {
	h := HashToken("secret")
	if len(h) != 64 {
		t.Errorf("expected 64-char hex string, got len %d: %q", len(h), h)
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character %q in hash %q", c, h)
		}
	}
}

func TestParseTokenID_Valid(t *testing.T) {
	id, secret, err := parseTokenID("abc123|mysecret")
	if err != nil {
		t.Fatal(err)
	}
	if id != "abc123" {
		t.Errorf("id = %q", id)
	}
	if secret != "mysecret" {
		t.Errorf("secret = %q", secret)
	}
}

func TestParseTokenID_InvalidFormats(t *testing.T) {
	invalids := []string{
		"",
		"nopipe",
		"|nosecret",
		"noid|", // empty secret
	}
	for _, tc := range invalids {
		_, _, err := parseTokenID(tc)
		if err == nil {
			t.Errorf("parseTokenID(%q) expected error, got nil", tc)
		}
	}
	// Valid case
	_, _, err := parseTokenID("id|secret")
	if err != nil {
		t.Errorf("parseTokenID(id|secret) unexpected error: %v", err)
	}
}

func TestIsExpired(t *testing.T) {
	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)

	if !(&Token{ExpiresAt: &past}).IsExpired() {
		t.Error("past ExpiresAt should be expired")
	}
	if (&Token{ExpiresAt: &future}).IsExpired() {
		t.Error("future ExpiresAt should not be expired")
	}
	if (&Token{}).IsExpired() {
		t.Error("nil ExpiresAt should not be expired")
	}
}

func TestGenerateUUID_Format(t *testing.T) {
	id, err := generateUUID()
	if err != nil {
		t.Fatal(err)
	}
	// UUID v4 format: 8-4-4-4-12 hex chars
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 UUID segments, got %d: %q", len(parts), id)
	}
	lengths := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != lengths[i] {
			t.Errorf("segment %d: len=%d, want %d", i, len(p), lengths[i])
		}
	}
}

func TestGenerateUUID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		id, err := generateUUID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatal("duplicate UUID")
		}
		seen[id] = true
	}
}
