package sanctum_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/hasbyte1/go-laravel-utils/sanctum/inmemory"
)

// exampleUser is a minimal User for the examples.
type exampleUser struct{ id string }

func (u *exampleUser) GetID() string { return u.id }

// newExampleService builds a TokenService with one registered user.
func newExampleService() *sanctum.TokenService {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&exampleUser{id: "user-123"})
	return sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
}

// Example_createAndAuthenticateToken demonstrates the basic token lifecycle.
func Example_createAndAuthenticateToken() {
	svc := newExampleService()
	ctx := context.Background()

	// Create a token with two abilities.
	result, err := svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{
		Name:      "My CLI Token",
		Abilities: []string{"servers:read", "servers:write"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("Token created:", result.Token.Name)

	// Authenticate using the plain-text token.
	user, token, err := svc.AuthenticateToken(ctx, result.PlainText, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Authenticated user:", user.GetID())
	fmt.Println("Token has servers:read:", sanctum.Can(token.Abilities, "servers:read"))
	fmt.Println("Token has billing:read:", sanctum.Can(token.Abilities, "billing:read"))

	// Output:
	// Token created: My CLI Token
	// Authenticated user: user-123
	// Token has servers:read: true
	// Token has billing:read: false
}

// Example_tokenExpiry demonstrates creating a token with an expiry time.
func Example_tokenExpiry() {
	svc := newExampleService()
	ctx := context.Background()

	past := time.Now().Add(-time.Second)
	result, _ := svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{
		Name:      "Short-lived Token",
		ExpiresAt: &past,
	})

	_, _, err := svc.AuthenticateToken(ctx, result.PlainText, nil)
	fmt.Println("Error:", err)

	// Output:
	// Error: sanctum: token expired
}

// Example_revokeToken demonstrates revoking a specific token.
func Example_revokeToken() {
	svc := newExampleService()
	ctx := context.Background()

	result, _ := svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{Name: "Deploy Key"})
	fmt.Println("Created:", result.Token.Name)

	svc.RevokeToken(ctx, result.Token.ID)

	_, _, err := svc.AuthenticateToken(ctx, result.PlainText, nil)
	fmt.Println("After revoke:", err)

	// Output:
	// Created: Deploy Key
	// After revoke: sanctum: token not found
}

// Example_abilities demonstrates AND / OR ability checking.
func Example_abilities() {
	abilities := []string{"servers:read", "servers:write"}

	fmt.Println("Can servers:read:", sanctum.Can(abilities, "servers:read"))
	fmt.Println("Can billing:read:", sanctum.Can(abilities, "billing:read"))
	fmt.Println("CanAll [servers:read, servers:write]:", sanctum.CanAll(abilities, []string{"servers:read", "servers:write"}))
	fmt.Println("CanAll [servers:read, billing:read]:", sanctum.CanAll(abilities, []string{"servers:read", "billing:read"}))
	fmt.Println("CanAny [billing:read, servers:write]:", sanctum.CanAny(abilities, []string{"billing:read", "servers:write"}))

	// Output:
	// Can servers:read: true
	// Can billing:read: false
	// CanAll [servers:read, servers:write]: true
	// CanAll [servers:read, billing:read]: false
	// CanAny [billing:read, servers:write]: true
}

// Example_hashToken demonstrates hashing a token secret for storage.
func Example_hashToken() {
	h := sanctum.HashToken("my-secret-value")
	fmt.Println("Hash length:", len(h))
	fmt.Println("Same input same hash:", h == sanctum.HashToken("my-secret-value"))
	fmt.Println("Different input different hash:", h != sanctum.HashToken("other-value"))

	// Output:
	// Hash length: 64
	// Same input same hash: true
	// Different input different hash: true
}

// Example_middleware demonstrates using Authenticate and RequireAbilities middleware.
func Example_middleware() {
	repo := inmemory.New()
	users := inmemory.NewUserStore()
	users.Add(&exampleUser{id: "user-456"})
	svc := sanctum.NewTokenService(repo, users, sanctum.DefaultConfig())
	csrf := sanctum.NewCSRFService(sanctum.DefaultConfig())
	guard := sanctum.NewGuard(svc, csrf)

	// Create a token with the "posts:write" ability.
	result, _ := svc.CreateToken(context.Background(), "user-456", sanctum.CreateTokenOptions{
		Abilities: []string{"posts:write"},
	})

	// Build a protected handler chain.
	protected := sanctum.Authenticate(guard)(
		sanctum.RequireAbilities("posts:write")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ac := sanctum.AuthContextFromRequest(r)
				fmt.Fprintf(w, "Hello, %s", ac.User.GetID())
			}),
		),
	)

	// Authorised request.
	req := httptest.NewRequest(http.MethodGet, "/posts", nil)
	req.Header.Set("Authorization", "Bearer "+result.PlainText)
	w := httptest.NewRecorder()
	protected.ServeHTTP(w, req)
	fmt.Println("Authorised status:", w.Code)
	fmt.Println("Body:", w.Body.String())

	// Unauthorised request (no header).
	req2 := httptest.NewRequest(http.MethodGet, "/posts", nil)
	w2 := httptest.NewRecorder()
	protected.ServeHTTP(w2, req2)
	fmt.Println("No token status:", w2.Code)

	// Output:
	// Authorised status: 200
	// Body: Hello, user-456
	// No token status: 401
}

// Example_csrf demonstrates issuing and validating CSRF tokens for SPA auth.
func Example_csrf() {
	cfg := sanctum.DefaultConfig()
	csrf := sanctum.NewCSRFService(cfg)

	// Server issues CSRF token (e.g. on GET /sanctum/csrf-cookie).
	w := httptest.NewRecorder()
	token, _ := csrf.IssueToken(w)
	fmt.Println("CSRF token issued:", token != "")

	// Client echoes cookie value in header on state-changing request.
	r := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	r.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: token})
	r.Header.Set("X-XSRF-TOKEN", token)

	err := csrf.ValidateRequest(r)
	fmt.Println("Valid request error:", err)

	// Tampered header.
	r2 := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	r2.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: token})
	r2.Header.Set("X-XSRF-TOKEN", "wrong-value")
	err2 := csrf.ValidateRequest(r2)
	fmt.Println("Tampered error:", err2)

	// Output:
	// CSRF token issued: true
	// Valid request error: <nil>
	// Tampered error: sanctum: CSRF token mismatch
}

// Example_pruneExpired demonstrates cleaning up expired tokens.
func Example_pruneExpired() {
	svc := newExampleService()
	ctx := context.Background()

	past := time.Now().Add(-time.Second)
	svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{ExpiresAt: &past, Name: "old-1"})
	svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{ExpiresAt: &past, Name: "old-2"})
	svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{Name: "active"})

	n, _ := svc.PruneExpired(ctx)
	fmt.Println("Pruned:", n)
	tokens, _ := svc.ListTokens(ctx, "user-123")
	fmt.Println("Remaining:", len(tokens))

	// Output:
	// Pruned: 2
	// Remaining: 1
}

// Example_otpVerification demonstrates token creation with OTP and verification.
func Example_otpVerification() {
	svc := newExampleService()
	ctx := context.Background()

	// Create a token with OTP requirement (e.g., 123456 sent via SMS)
	otp := int32(123456)
	otpType := "sms"
	result, err := svc.CreateToken(ctx, "user-123", sanctum.CreateTokenOptions{
		Name:      "SMS-Protected Token",
		Abilities: []string{"admin"},
		OTP:       &otp,
		OTPType:   &otpType,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("Token created with OTP requirement")

	// Try to authenticate without verifying OTP - should fail
	_, _, err = svc.AuthenticateToken(ctx, result.PlainText, nil)
	fmt.Println("Auth without OTP:", err) // ErrOTPRequired

	// Verify OTP with wrong code - should fail and increment attempts
	_, err = svc.VerifyOTP(ctx, result.Token.ID, 999999, nil)
	fmt.Println("Wrong OTP:", err) // ErrInvalidOTP

	// Verify with correct OTP
	_, err = svc.VerifyOTP(ctx, result.Token.ID, otp, nil)
	fmt.Println("Correct OTP verification:", err == nil)

	// Now authentication should succeed
	user, token, err := svc.AuthenticateToken(ctx, result.PlainText, nil)
	fmt.Println("Auth after OTP:", err == nil)
	fmt.Println("User:", user.GetID())
	fmt.Println("Token requires OTP:", token.RequiresOTP())

	// Output:
	// Token created with OTP requirement
	// Auth without OTP: sanctum: OTP verification required
	// Wrong OTP: sanctum: invalid OTP
	// Correct OTP verification: true
	// Auth after OTP: true
	// User: user-123
	// Token requires OTP: false
}
