package passport

import (
	"context"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// minClientStore always returns ErrClientNotFound — simulates a deleted client.
type minClientStore struct{}

func (m *minClientStore) GetClient(_ context.Context, _ string) (*OAuthClient, error) {
	return nil, ErrClientNotFound
}

// minAuthCodeStore is a minimal in-memory AuthorizationCodeStore for testing.
type minAuthCodeStore struct {
	codes map[string]*AuthorizationCode
}

func (m *minAuthCodeStore) CreateAuthorizationCode(_ context.Context, code *AuthorizationCode) error {
	cp := *code
	m.codes[code.Code] = &cp
	return nil
}

func (m *minAuthCodeStore) GetAuthorizationCode(_ context.Context, code string) (*AuthorizationCode, error) {
	ac, ok := m.codes[code]
	if !ok {
		return nil, ErrCodeNotFound
	}
	cp := *ac
	if !ac.Active {
		return &cp, ErrCodeInvalidated
	}
	return &cp, nil
}

func (m *minAuthCodeStore) InvalidateAuthorizationCode(_ context.Context, code string) error {
	if ac, ok := m.codes[code]; ok {
		ac.Active = false
	}
	return nil
}

func (m *minAuthCodeStore) DeleteAuthorizationCode(_ context.Context, code string) error {
	delete(m.codes, code)
	return nil
}

// TestGetAuthorizeCodeSession_replayWithUnresolvableClient verifies that replaying
// an auth code whose client has since been deleted returns a non-nil requester so
// fosite can safely call req.GetID() for token revocation without panicking.
func TestGetAuthorizeCodeSession_replayWithUnresolvableClient_returnsNonNilRequester(t *testing.T) {
	codeStore := &minAuthCodeStore{codes: make(map[string]*AuthorizationCode)}
	a := newAdapter(&minClientStore{}, codeStore, nil, nil, nil, nil)

	ctx := context.Background()

	_ = codeStore.CreateAuthorizationCode(ctx, &AuthorizationCode{
		Code:      "replay-code",
		RequestID: "req-replay-123",
		ClientID:  "deleted-client",
		Active:    true,
	})
	_ = codeStore.InvalidateAuthorizationCode(ctx, "replay-code")

	sess := newEmptySession()
	req, err := a.GetAuthorizeCodeSession(ctx, "replay-code", sess)

	if err != fosite.ErrInvalidatedAuthorizeCode {
		t.Fatalf("expected ErrInvalidatedAuthorizeCode, got %v", err)
	}
	if req == nil {
		t.Fatal("req must not be nil when returning ErrInvalidatedAuthorizeCode — fosite calls req.GetID() for revocation")
	}
	if req.GetID() != "req-replay-123" {
		t.Fatalf("expected RequestID %q, got %q", "req-replay-123", req.GetID())
	}
}

// TestFositeClient_GetResponseTypes_authCodeOnly verifies that a client configured
// only for authorization_code does not advertise the implicit grant response type ("token").
func TestFositeClient_GetResponseTypes_authCodeOnly(t *testing.T) {
	fc := &fositeClient{c: &OAuthClient{
		GrantTypes: []string{"authorization_code"},
	}}
	got := fc.GetResponseTypes()

	for _, rt := range got {
		if rt == "token" {
			t.Fatal("authorization_code-only client must not advertise response_type=token (implicit grant)")
		}
	}
	found := false
	for _, rt := range got {
		if rt == "code" {
			found = true
		}
	}
	if !found {
		t.Fatalf("authorization_code client must advertise response_type=code, got %v", got)
	}
}

// TestFositeClient_GetResponseTypes_clientCredentials verifies that a client
// configured only for client_credentials has no response types (no interactive flow).
func TestFositeClient_GetResponseTypes_clientCredentials(t *testing.T) {
	fc := &fositeClient{c: &OAuthClient{
		GrantTypes: []string{"client_credentials"},
	}}
	got := fc.GetResponseTypes()
	if len(got) != 0 {
		t.Fatalf("client_credentials client must have no response types, got %v", got)
	}
}

// TestCombinedSession_Clone_preservesExtraClaims verifies that Clone() produces
// a deep copy of ExtraClaims so mutations to the clone do not affect the original.
func TestCombinedSession_Clone_preservesExtraClaims(t *testing.T) {
	orig := &combinedSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Subject: "user-42"},
			Headers: &jwt.Headers{},
			Subject: "user-42",
		},
		ExtraClaims: map[string]any{
			"role":   "admin",
			"org_id": "org-1",
		},
	}

	cloned := orig.Clone()

	cs, ok := cloned.(*combinedSession)
	if !ok {
		t.Fatalf("Clone() must return *combinedSession, got %T", cloned)
	}

	// ExtraClaims must be copied with the same values.
	if cs.ExtraClaims["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", cs.ExtraClaims["role"])
	}
	if cs.ExtraClaims["org_id"] != "org-1" {
		t.Errorf("expected org_id=org-1, got %v", cs.ExtraClaims["org_id"])
	}

	// Mutating the clone must not affect the original.
	cs.ExtraClaims["role"] = "viewer"
	if orig.ExtraClaims["role"] != "admin" {
		t.Error("Clone() is not a deep copy: mutating clone changed the original ExtraClaims")
	}
}

// TestCombinedSession_Clone_implementsJWTSessionContainer verifies that the value
// returned by Clone() satisfies oauth2.JWTSessionContainer — the contract required
// by fosite's refresh-token grant to issue JWT access tokens.
func TestCombinedSession_Clone_implementsJWTSessionContainer(t *testing.T) {
	orig := &combinedSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Subject: "user-1"},
			Headers: &jwt.Headers{},
			Subject: "user-1",
		},
		ExtraClaims: map[string]any{"k": "v"},
	}

	cloned := orig.Clone()

	if _, ok := cloned.(oauth2.JWTSessionContainer); !ok {
		t.Fatalf("Clone() result %T does not implement oauth2.JWTSessionContainer; "+
			"the refresh-token grant will panic at runtime", cloned)
	}
}

// TestCombinedSession_Clone_nilSafe verifies that calling Clone() on a nil
// *combinedSession returns nil rather than panicking.
func TestCombinedSession_Clone_nilSafe(t *testing.T) {
	var s *combinedSession
	got := s.Clone()
	if got != nil {
		t.Fatalf("Clone() on nil must return nil, got %v", got)
	}
}

// TestCombinedSession_Clone_nilDefaultSession verifies that Clone() does not panic
// when DefaultSession is nil on a non-nil receiver (e.g. after unmarshalSession
// deserializes a zero-value blob), and that it returns a valid *combinedSession
// with non-nil Claims and Headers.
func TestCombinedSession_Clone_nilDefaultSession(t *testing.T) {
	s := &combinedSession{DefaultSession: nil, ExtraClaims: map[string]any{"k": "v"}}

	var cloned fosite.Session
	// Must not panic.
	cloned = s.Clone()

	cs, ok := cloned.(*combinedSession)
	if !ok {
		t.Fatalf("Clone() must return *combinedSession, got %T", cloned)
	}
	if cs.DefaultSession == nil {
		t.Fatal("Clone() must initialise DefaultSession when source is nil")
	}
	if cs.DefaultSession.Claims == nil {
		t.Fatal("Clone() must initialise DefaultSession.Claims")
	}
	if cs.DefaultSession.Headers == nil {
		t.Fatal("Clone() must initialise DefaultSession.Headers")
	}
	if cs.ExtraClaims["k"] != "v" {
		t.Errorf("ExtraClaims not copied: got %v", cs.ExtraClaims["k"])
	}
}

// TestCombinedSession_Clone_nilDefaultSession_implementsJWTSessionContainer verifies
// that the value returned by Clone() when DefaultSession was nil still satisfies
// oauth2.JWTSessionContainer — required by fosite's refresh-token grant.
func TestCombinedSession_Clone_nilDefaultSession_implementsJWTSessionContainer(t *testing.T) {
	s := &combinedSession{DefaultSession: nil}
	cloned := s.Clone()
	if _, ok := cloned.(oauth2.JWTSessionContainer); !ok {
		t.Fatalf("Clone() result %T does not implement oauth2.JWTSessionContainer", cloned)
	}
}
