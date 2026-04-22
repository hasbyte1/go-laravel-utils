package inmemory_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hasbyte1/go-laravel-utils/passport"
	"github.com/hasbyte1/go-laravel-utils/passport/inmemory"
)

// --- Store (ClientStore + all token stores) ---

func TestStore_GetClient_found(t *testing.T) {
	s := inmemory.New()
	s.AddClient(&passport.OAuthClient{ID: "c1", Scopes: []string{"openid"}})
	got, err := s.GetClient(context.Background(), "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "c1" {
		t.Fatalf("got ID %q, want %q", got.ID, "c1")
	}
}

func TestStore_GetClient_notFound(t *testing.T) {
	s := inmemory.New()
	_, err := s.GetClient(context.Background(), "missing")
	if err != passport.ErrClientNotFound {
		t.Fatalf("got %v, want ErrClientNotFound", err)
	}
}

func TestStore_AuthorizationCode_lifecycle(t *testing.T) {
	s := inmemory.New()
	ctx := context.Background()
	code := &passport.AuthorizationCode{
		Code:      "abc",
		ClientID:  "c1",
		UserID:    "u1",
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(time.Minute),
		Active:    true,
	}
	if err := s.CreateAuthorizationCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAuthorizationCode(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" {
		t.Fatalf("got UserID %q", got.UserID)
	}
	if err := s.InvalidateAuthorizationCode(ctx, "abc"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetAuthorizationCode(ctx, "abc")
	if err != passport.ErrCodeInvalidated {
		t.Fatalf("got %v, want ErrCodeInvalidated", err)
	}
	if err := s.DeleteAuthorizationCode(ctx, "abc"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetAuthorizationCode(ctx, "abc")
	if err != passport.ErrCodeNotFound {
		t.Fatalf("got %v, want ErrCodeNotFound after delete", err)
	}
}

func TestStore_AccessToken_lifecycle(t *testing.T) {
	s := inmemory.New()
	ctx := context.Background()
	tok := &passport.AccessToken{
		Signature: "sig1",
		RequestID: "req1",
		ClientID:  "c1",
		UserID:    "u1",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateAccessToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAccessToken(ctx, "sig1")
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "req1" {
		t.Fatalf("got RequestID %q", got.RequestID)
	}
	if err := s.DeleteAccessTokensByRequestID(ctx, "req1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.GetAccessToken(ctx, "sig1")
	if err != passport.ErrTokenNotFound {
		t.Fatalf("got %v, want ErrTokenNotFound", err)
	}
}

func TestStore_RefreshToken_revoke(t *testing.T) {
	s := inmemory.New()
	ctx := context.Background()
	tok := &passport.RefreshToken{
		Signature: "rsig1",
		RequestID: "req2",
		ClientID:  "c1",
		UserID:    "u1",
		Active:    true,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateRefreshToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRefreshTokensByRequestID(ctx, "req2"); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetRefreshToken(ctx, "rsig1")
	if err != passport.ErrTokenInactive {
		t.Fatalf("got %v, want ErrTokenInactive", err)
	}
}

func TestStore_DeviceCode_lifecycle(t *testing.T) {
	s := inmemory.New()
	ctx := context.Background()
	dc := &passport.DeviceCode{
		DeviceCode: "dcode1",
		UserCode:   "ABCD-1234",
		RequestID:  "req3",
		ClientID:   "c1",
		Scopes:     []string{"openid"},
		ExpiresAt:  time.Now().Add(5 * time.Minute),
		Status:     passport.DeviceStatusPending,
		Interval:   5,
	}
	if err := s.CreateDeviceCode(ctx, dc); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDeviceCodeByUserCode(ctx, "ABCD-1234")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceCode != "dcode1" {
		t.Fatalf("wrong device code")
	}
	got.Status = passport.DeviceStatusApproved
	got.UserID = "u1"
	if err := s.UpdateDeviceCode(ctx, got); err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetDeviceCode(ctx, "dcode1")
	if err != nil {
		t.Fatal(err)
	}
	if got2.Status != passport.DeviceStatusApproved {
		t.Fatalf("status not updated")
	}
}

// --- ConsentStore ---

func TestConsentStore_autoApprove(t *testing.T) {
	cs := inmemory.NewConsentStore()
	ctx := context.Background()
	ok, err := cs.IsConsentGranted(ctx, "u1", "c1", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("auto-consent store should always return true")
	}
}

// --- SessionStore ---

type testUser struct{ id string }

func (u *testUser) GetID() string { return u.id }

func TestSessionStore_roundtrip(t *testing.T) {
	ss := inmemory.NewSessionStore()
	u := &testUser{id: "u99"}
	ss.Set("cookie-abc", u)

	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-abc"})

	got, err := ss.GetUser(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.GetID() != "u99" {
		t.Fatalf("wrong user returned")
	}
}

func TestSessionStore_missing(t *testing.T) {
	ss := inmemory.NewSessionStore()
	r, _ := http.NewRequest("GET", "/", nil)
	got, err := ss.GetUser(context.Background(), r)
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil got %v,%v", got, err)
	}
}
