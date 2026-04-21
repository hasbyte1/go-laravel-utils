package passport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// adapter implements all fosite storage interfaces by delegating to the consumer's
// simple interfaces. It is an internal type — consumers never import fosite.
type adapter struct {
	clients     ClientStore
	authCodes   AuthorizationCodeStore
	accessToks  AccessTokenStore
	refreshToks RefreshTokenStore
	devices     DeviceStore
	users       sanctum.UserProvider

	mu           sync.RWMutex
	pkceSessions map[string][]byte    // auth code → serialized fosite.Requester
	oidcSessions map[string][]byte    // auth code → serialized fosite.Requester
	jtiDenylist  map[string]time.Time // JWT assertion JTIs
	reqToDevice  map[string]string    // fosite requestID → device code string
}

func newAdapter(
	clients ClientStore,
	authCodes AuthorizationCodeStore,
	accessToks AccessTokenStore,
	refreshToks RefreshTokenStore,
	devices DeviceStore,
	users sanctum.UserProvider,
) *adapter {
	return &adapter{
		clients:      clients,
		authCodes:    authCodes,
		accessToks:   accessToks,
		refreshToks:  refreshToks,
		devices:      devices,
		users:        users,
		pkceSessions: make(map[string][]byte),
		oidcSessions: make(map[string][]byte),
		jtiDenylist:  make(map[string]time.Time),
		reqToDevice:  make(map[string]string),
	}
}

// -----------------------------------------------------------------------
// fosite.ClientManager
// -----------------------------------------------------------------------

func (a *adapter) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, err := a.clients.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	return &fositeClient{c: c}, nil
}

func (a *adapter) ClientAssertionJWTValid(_ context.Context, jti string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if exp, ok := a.jtiDenylist[jti]; ok && time.Now().Before(exp) {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (a *adapter) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.jtiDenylist[jti] = exp
	return nil
}

// -----------------------------------------------------------------------
// oauth2.AuthorizeCodeStorage
// -----------------------------------------------------------------------

func (a *adapter) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	data, err := marshalSession(req.GetSession())
	if err != nil {
		return fmt.Errorf("passport adapter: marshal auth code session: %w", err)
	}
	userID := ""
	if sess, ok := req.GetSession().(*openid.DefaultSession); ok {
		userID = sess.Subject
	}
	ac := &AuthorizationCode{
		Code:        code,
		ClientID:    req.GetClient().GetID(),
		UserID:      userID,
		RedirectURI: req.GetRequestForm().Get("redirect_uri"),
		Scopes:      req.GetGrantedScopes(),
		ExpiresAt:   req.GetSession().GetExpiresAt(fosite.AuthorizeCode),
		Active:      true,
		SessionData: data,
		Nonce:       req.GetRequestForm().Get("nonce"),
	}
	return a.authCodes.CreateAuthorizationCode(ctx, ac)
}

func (a *adapter) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	ac, err := a.authCodes.GetAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return nil, fosite.ErrNotFound
		}
		if errors.Is(err, ErrCodeInvalidated) {
			req, _ := a.buildRequesterFromCode(ctx, ac, session)
			return req, fosite.ErrInvalidatedAuthorizeCode
		}
		return nil, err
	}
	return a.buildRequesterFromCode(ctx, ac, session)
}

func (a *adapter) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return a.authCodes.InvalidateAuthorizationCode(ctx, code)
}

// -----------------------------------------------------------------------
// oauth2.AccessTokenStorage
// -----------------------------------------------------------------------

func (a *adapter) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := marshalSession(req.GetSession())
	if err != nil {
		return err
	}
	userID := ""
	if sess, ok := req.GetSession().(*openid.DefaultSession); ok {
		userID = sess.Subject
	}
	tok := &AccessToken{
		Signature:   signature,
		RequestID:   req.GetID(),
		ClientID:    req.GetClient().GetID(),
		UserID:      userID,
		Scopes:      req.GetGrantedScopes(),
		ExpiresAt:   req.GetSession().GetExpiresAt(fosite.AccessToken),
		SessionData: data,
	}
	return a.accessToks.CreateAccessToken(ctx, tok)
}

func (a *adapter) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	tok, err := a.accessToks.GetAccessToken(ctx, signature)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	c, err := a.clients.GetClient(ctx, tok.ClientID)
	if err != nil {
		return nil, err
	}
	if err := unmarshalSession(tok.SessionData, session); err != nil {
		return nil, err
	}
	return buildRequest(c, tok.Scopes, tok.RequestID, session), nil
}

func (a *adapter) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return a.accessToks.DeleteAccessToken(ctx, signature)
}

// -----------------------------------------------------------------------
// oauth2.RefreshTokenStorage
//
// Note: fosite v0.49 RefreshTokenStorage has a 3-arg CreateRefreshTokenSession
// (signature, accessSignature string, req Requester) and RotateRefreshToken
// instead of RevokeRefreshTokenMaybeGracePeriod.
// -----------------------------------------------------------------------

func (a *adapter) CreateRefreshTokenSession(ctx context.Context, signature string, _ string, req fosite.Requester) error {
	data, err := marshalSession(req.GetSession())
	if err != nil {
		return err
	}
	userID := ""
	if sess, ok := req.GetSession().(*openid.DefaultSession); ok {
		userID = sess.Subject
	}
	tok := &RefreshToken{
		Signature:   signature,
		RequestID:   req.GetID(),
		ClientID:    req.GetClient().GetID(),
		UserID:      userID,
		Scopes:      req.GetGrantedScopes(),
		ExpiresAt:   req.GetSession().GetExpiresAt(fosite.RefreshToken),
		Active:      true,
		SessionData: data,
	}
	return a.refreshToks.CreateRefreshToken(ctx, tok)
}

func (a *adapter) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	tok, err := a.refreshToks.GetRefreshToken(ctx, signature)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		if errors.Is(err, ErrTokenInactive) {
			c, _ := a.clients.GetClient(ctx, tok.ClientID)
			_ = unmarshalSession(tok.SessionData, session)
			return buildRequest(c, tok.Scopes, tok.RequestID, session), fosite.ErrInactiveToken
		}
		return nil, err
	}
	c, err := a.clients.GetClient(ctx, tok.ClientID)
	if err != nil {
		return nil, err
	}
	if err := unmarshalSession(tok.SessionData, session); err != nil {
		return nil, err
	}
	return buildRequest(c, tok.Scopes, tok.RequestID, session), nil
}

func (a *adapter) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return a.refreshToks.DeleteRefreshToken(ctx, signature)
}

// RotateRefreshToken is called by fosite v0.49 refresh-token rotation.
// We delegate to RevokeRefreshTokensByRequestID which marks the old token inactive.
func (a *adapter) RotateRefreshToken(ctx context.Context, requestID string, _ string) error {
	return a.refreshToks.RevokeRefreshTokensByRequestID(ctx, requestID)
}

// -----------------------------------------------------------------------
// oauth2.TokenRevocationStorage (adds RevokeRefreshToken + RevokeAccessToken
// on top of the embedded RefreshTokenStorage + AccessTokenStorage)
// -----------------------------------------------------------------------

func (a *adapter) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return a.refreshToks.RevokeRefreshTokensByRequestID(ctx, requestID)
}

func (a *adapter) RevokeAccessToken(ctx context.Context, requestID string) error {
	return a.accessToks.DeleteAccessTokensByRequestID(ctx, requestID)
}

// -----------------------------------------------------------------------
// pkce.PKCERequestStorage
// -----------------------------------------------------------------------

func (a *adapter) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	data, err := marshalRequester(req)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.pkceSessions[code] = data
	a.mu.Unlock()
	return nil
}

func (a *adapter) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	a.mu.RLock()
	data, ok := a.pkceSessions[code]
	a.mu.RUnlock()
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return unmarshalRequester(ctx, data, session, a.clients)
}

func (a *adapter) DeletePKCERequestSession(_ context.Context, code string) error {
	a.mu.Lock()
	delete(a.pkceSessions, code)
	a.mu.Unlock()
	return nil
}

// -----------------------------------------------------------------------
// openid.OpenIDConnectRequestStorage
// -----------------------------------------------------------------------

func (a *adapter) CreateOpenIDConnectSession(_ context.Context, code string, req fosite.Requester) error {
	data, err := marshalRequester(req)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.oidcSessions[code] = data
	a.mu.Unlock()
	return nil
}

func (a *adapter) GetOpenIDConnectSession(ctx context.Context, code string, _ fosite.Requester) (fosite.Requester, error) {
	a.mu.RLock()
	data, ok := a.oidcSessions[code]
	a.mu.RUnlock()
	if !ok {
		return nil, fosite.ErrNotFound
	}
	sess := newEmptySession()
	return unmarshalRequester(ctx, data, sess, a.clients)
}

func (a *adapter) DeleteOpenIDConnectSession(_ context.Context, code string) error {
	a.mu.Lock()
	delete(a.oidcSessions, code)
	a.mu.Unlock()
	return nil
}

// -----------------------------------------------------------------------
// Device flow — DeviceStore is stored but fosite v0.49 has no device
// compose factory. Device approval/denial is handled directly via Server
// methods; these helpers exist for future extensibility.
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// fositeClient — implements fosite.Client wrapping *OAuthClient
// -----------------------------------------------------------------------

type fositeClient struct{ c *OAuthClient }

func (fc *fositeClient) GetID() string                      { return fc.c.ID }
func (fc *fositeClient) GetHashedSecret() []byte            { return []byte(fc.c.SecretHash) }
func (fc *fositeClient) GetRedirectURIs() []string          { return fc.c.RedirectURIs }
func (fc *fositeClient) GetGrantTypes() fosite.Arguments    { return fc.c.GrantTypes }
func (fc *fositeClient) GetResponseTypes() fosite.Arguments { return fosite.Arguments{"code", "token"} }
func (fc *fositeClient) GetScopes() fosite.Arguments        { return fc.c.Scopes }
func (fc *fositeClient) IsPublic() bool                     { return fc.c.Public }
func (fc *fositeClient) GetAudience() fosite.Arguments      { return fosite.Arguments{} }

// -----------------------------------------------------------------------
// session helpers
// -----------------------------------------------------------------------

func newEmptySession() *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims:  &jwt.IDTokenClaims{},
		Headers: &jwt.Headers{},
	}
}

func newSession(subject string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims:  &jwt.IDTokenClaims{Subject: subject},
		Headers: &jwt.Headers{},
		Subject: subject,
	}
}

func marshalSession(s fosite.Session) ([]byte, error) {
	return json.Marshal(s)
}

func unmarshalSession(data []byte, dst fosite.Session) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, dst)
}

type serializedRequester struct {
	ClientID    string          `json:"client_id"`
	RequestID   string          `json:"request_id"`
	Scopes      []string        `json:"scopes"`
	SessionData json.RawMessage `json:"session"`
}

func marshalRequester(req fosite.Requester) ([]byte, error) {
	sess, err := json.Marshal(req.GetSession())
	if err != nil {
		return nil, err
	}
	return json.Marshal(&serializedRequester{
		ClientID:    req.GetClient().GetID(),
		RequestID:   req.GetID(),
		Scopes:      req.GetGrantedScopes(),
		SessionData: sess,
	})
}

func unmarshalRequester(ctx context.Context, data []byte, session fosite.Session, clients ClientStore) (fosite.Requester, error) {
	var sr serializedRequester
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sr.SessionData, session); err != nil {
		return nil, err
	}
	c, err := clients.GetClient(ctx, sr.ClientID)
	if err != nil {
		return nil, err
	}
	return buildRequest(c, sr.Scopes, sr.RequestID, session), nil
}

func buildRequest(c *OAuthClient, scopes []string, requestID string, session fosite.Session) fosite.Requester {
	req := fosite.NewRequest()
	req.Client = &fositeClient{c: c}
	req.GrantedScope = scopes
	req.RequestedScope = scopes
	req.Session = session
	req.ID = requestID
	req.RequestedAt = time.Now()
	return req
}

func (a *adapter) buildRequesterFromCode(ctx context.Context, ac *AuthorizationCode, session fosite.Session) (fosite.Requester, error) {
	if err := unmarshalSession(ac.SessionData, session); err != nil {
		return nil, err
	}
	c, err := a.clients.GetClient(ctx, ac.ClientID)
	if err != nil {
		return nil, err
	}
	return buildRequest(c, ac.Scopes, "", session), nil
}
