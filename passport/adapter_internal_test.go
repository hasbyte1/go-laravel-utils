package passport

import (
	"context"
	"testing"

	"github.com/ory/fosite"
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
