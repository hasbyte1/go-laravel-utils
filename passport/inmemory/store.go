package inmemory

import (
	"context"
	"net/http"
	"sync"

	"github.com/hasbyte1/go-laravel-utils/passport"
	"github.com/hasbyte1/go-laravel-utils/sanctum"
)

// Store is a thread-safe in-memory implementation of ClientStore,
// AuthorizationCodeStore, AccessTokenStore, RefreshTokenStore, and DeviceStore.
type Store struct {
	mu       sync.RWMutex
	clients  map[string]*passport.OAuthClient
	codes    map[string]*passport.AuthorizationCode // keyed by code string
	access   map[string]*passport.AccessToken       // keyed by signature
	refresh  map[string]*passport.RefreshToken      // keyed by signature
	devices  map[string]*passport.DeviceCode        // keyed by device_code
	userCode map[string]string                      // user_code → device_code
}

// New creates an empty Store.
func New() *Store {
	return &Store{
		clients:  make(map[string]*passport.OAuthClient),
		codes:    make(map[string]*passport.AuthorizationCode),
		access:   make(map[string]*passport.AccessToken),
		refresh:  make(map[string]*passport.RefreshToken),
		devices:  make(map[string]*passport.DeviceCode),
		userCode: make(map[string]string),
	}
}

// AddClient registers a client in the store. Overwrites any existing client with the same ID.
func (s *Store) AddClient(c *passport.OAuthClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.clients[c.ID] = &cp
}

// GetClient implements ClientStore.
func (s *Store) GetClient(_ context.Context, id string) (*passport.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, passport.ErrClientNotFound
	}
	cp := *c
	return &cp, nil
}

// --- AuthorizationCodeStore ---

func (s *Store) CreateAuthorizationCode(_ context.Context, code *passport.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cloneCode(code)
	s.codes[code.Code] = cp
	return nil
}

func (s *Store) GetAuthorizationCode(_ context.Context, code string) (*passport.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, passport.ErrCodeNotFound
	}
	if !c.Active {
		cp := cloneCode(c)
		return cp, passport.ErrCodeInvalidated
	}
	return cloneCode(c), nil
}

func (s *Store) InvalidateAuthorizationCode(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return passport.ErrCodeNotFound
	}
	c.Active = false
	return nil
}

func (s *Store) DeleteAuthorizationCode(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
	return nil
}

// --- AccessTokenStore ---

func (s *Store) CreateAccessToken(_ context.Context, tok *passport.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cloneAccessToken(tok)
	s.access[tok.Signature] = cp
	return nil
}

func (s *Store) GetAccessToken(_ context.Context, sig string) (*passport.AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.access[sig]
	if !ok {
		return nil, passport.ErrTokenNotFound
	}
	return cloneAccessToken(t), nil
}

func (s *Store) DeleteAccessToken(_ context.Context, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.access, sig)
	return nil
}

func (s *Store) DeleteAccessTokensBySubject(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, t := range s.access {
		if t.UserID == subject {
			delete(s.access, sig)
		}
	}
	return nil
}

func (s *Store) DeleteAccessTokensByRequestID(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, t := range s.access {
		if t.RequestID == requestID {
			delete(s.access, sig)
		}
	}
	return nil
}

// --- RefreshTokenStore ---

func (s *Store) CreateRefreshToken(_ context.Context, tok *passport.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[tok.Signature] = cloneRefreshToken(tok)
	return nil
}

func (s *Store) GetRefreshToken(_ context.Context, sig string) (*passport.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.refresh[sig]
	if !ok {
		return nil, passport.ErrTokenNotFound
	}
	if !t.Active {
		return cloneRefreshToken(t), passport.ErrTokenInactive
	}
	return cloneRefreshToken(t), nil
}

func (s *Store) DeleteRefreshToken(_ context.Context, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refresh, sig)
	return nil
}

func (s *Store) DeleteRefreshTokensBySubject(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, t := range s.refresh {
		if t.UserID == subject {
			delete(s.refresh, sig)
		}
	}
	return nil
}

func (s *Store) RevokeRefreshTokensByRequestID(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.refresh {
		if t.RequestID == requestID {
			t.Active = false
		}
	}
	return nil
}

// --- DeviceStore ---

func (s *Store) CreateDeviceCode(_ context.Context, dc *passport.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cloneDevice(dc)
	s.devices[dc.DeviceCode] = cp
	if dc.UserCode != "" {
		s.userCode[dc.UserCode] = dc.DeviceCode
	}
	return nil
}

func (s *Store) GetDeviceCode(_ context.Context, deviceCode string) (*passport.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dc, ok := s.devices[deviceCode]
	if !ok {
		return nil, passport.ErrDeviceNotFound
	}
	return cloneDevice(dc), nil
}

func (s *Store) GetDeviceCodeByUserCode(_ context.Context, userCode string) (*passport.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	deviceCode, ok := s.userCode[userCode]
	if !ok {
		return nil, passport.ErrDeviceNotFound
	}
	dc, ok := s.devices[deviceCode]
	if !ok {
		return nil, passport.ErrDeviceNotFound
	}
	return cloneDevice(dc), nil
}

func (s *Store) UpdateDeviceCode(_ context.Context, dc *passport.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.devices[dc.DeviceCode]
	if !ok {
		return passport.ErrDeviceNotFound
	}
	if existing.UserCode == "" && dc.UserCode != "" {
		s.userCode[dc.UserCode] = dc.DeviceCode
	}
	s.devices[dc.DeviceCode] = cloneDevice(dc)
	return nil
}

func (s *Store) DeleteDeviceCode(_ context.Context, deviceCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dc, ok := s.devices[deviceCode]
	if !ok {
		return passport.ErrDeviceNotFound
	}
	delete(s.userCode, dc.UserCode)
	delete(s.devices, deviceCode)
	return nil
}

// --- ConsentStore ---

// ConsentStore is an in-memory ConsentProvider that auto-approves all requests.
// Useful for tests. Replace with a real implementation in production.
type ConsentStore struct{}

// NewConsentStore creates a ConsentStore that auto-approves every consent check.
func NewConsentStore() *ConsentStore {
	return &ConsentStore{}
}

func (c *ConsentStore) IsConsentGranted(_ context.Context, _, _ string, _ []string) (bool, error) {
	return true, nil
}

func (c *ConsentStore) SaveConsent(_ context.Context, _, _ string, _ []string) error {
	return nil
}

func (c *ConsentStore) RevokeConsent(_ context.Context, _, _ string) error {
	return nil
}

// --- SessionStore ---

// SessionStore is an in-memory UserSessionProvider that resolves users by a
// named cookie value. Call Set to register cookie → user mappings in tests.
type SessionStore struct {
	mu         sync.RWMutex
	users      map[string]sanctum.User
	CookieName string
}

// NewSessionStore creates an empty SessionStore using cookie name "session".
func NewSessionStore() *SessionStore {
	return &SessionStore{
		users:      make(map[string]sanctum.User),
		CookieName: "session",
	}
}

// Set registers a cookie value → user mapping.
func (s *SessionStore) Set(cookieValue string, user sanctum.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[cookieValue] = user
}

// GetUser implements UserSessionProvider. Returns (nil, nil) when no session cookie is present.
func (s *SessionStore) GetUser(_ context.Context, r *http.Request) (sanctum.User, error) {
	name := s.CookieName
	if name == "" {
		name = "session"
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[cookie.Value]
	if !ok {
		return nil, nil
	}
	return u, nil
}

// --- clone helpers ---

func cloneCode(c *passport.AuthorizationCode) *passport.AuthorizationCode {
	cp := *c
	cp.Scopes = cloneStrings(c.Scopes)
	cp.SessionData = cloneBytes(c.SessionData)
	return &cp
}

func cloneAccessToken(t *passport.AccessToken) *passport.AccessToken {
	cp := *t
	cp.Scopes = cloneStrings(t.Scopes)
	cp.SessionData = cloneBytes(t.SessionData)
	return &cp
}

func cloneRefreshToken(t *passport.RefreshToken) *passport.RefreshToken {
	cp := *t
	cp.Scopes = cloneStrings(t.Scopes)
	cp.SessionData = cloneBytes(t.SessionData)
	return &cp
}

func cloneDevice(d *passport.DeviceCode) *passport.DeviceCode {
	cp := *d
	cp.Scopes = cloneStrings(d.Scopes)
	cp.SessionData = cloneBytes(d.SessionData)
	return &cp
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
