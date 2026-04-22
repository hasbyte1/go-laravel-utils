package passport

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/hasbyte1/go-laravel-utils/sanctum"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
)

// Server is the OAuth2/OIDC authorization server.
type Server struct {
	provider  fosite.OAuth2Provider
	config    Config
	adapter   *adapter
	sessions  UserSessionProvider
	consent   ConsentProvider
	userInfo  UserInfoProvider
	users     sanctum.UserProvider
	devices   DeviceStore
	publicKey any // *rsa.PublicKey
	enricher  func(ctx context.Context, userID string) (map[string]any, error)
}

// ServerOption is a functional option for Server.
type ServerOption func(*Server)

// WithSessionEnricher injects extra JWT claims (e.g. name, is_admin, roles) into
// the access token during the authorize flow. fn is called with the authenticated
// user's ID immediately before NewAuthorizeResponse.
func WithSessionEnricher(fn func(ctx context.Context, userID string) (map[string]any, error)) ServerOption {
	return func(s *Server) { s.enricher = fn }
}

// NewServer constructs a Server, wiring all consumer stores into fosite.
// key must be an *rsa.PrivateKey (RS256).
func NewServer(
	cfg Config,
	clients ClientStore,
	authCodes AuthorizationCodeStore,
	accessToks AccessTokenStore,
	refreshToks RefreshTokenStore,
	devices DeviceStore,
	sessions UserSessionProvider,
	consent ConsentProvider,
	userInfo UserInfoProvider,
	users sanctum.UserProvider,
	key *rsa.PrivateKey,
	opts ...ServerOption,
) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("passport: Config.Issuer is required")
	}
	if len(cfg.GlobalSecret) < 32 {
		return nil, errors.New("passport: Config.GlobalSecret must be at least 32 bytes")
	}

	applyDefaults(&cfg)

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            cfg.AccessTokenTTL,
		RefreshTokenLifespan:           cfg.RefreshTokenTTL,
		AuthorizeCodeLifespan:          cfg.AuthCodeTTL,
		IDTokenIssuer:                  cfg.Issuer,
		AccessTokenIssuer:              cfg.Issuer,
		GlobalSecret:                   cfg.GlobalSecret,
		SendDebugMessagesToClients:     false,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	ad := newAdapter(clients, authCodes, accessToks, refreshToks, devices, users)

	// Build a CommonStrategy that satisfies both oauth2.CoreStrategy (for JWT access tokens)
	// and openid.OpenIDConnectTokenStrategy (for ID tokens). fosite v0.49 requires
	// OpenIDConnectExplicitFactory to receive a strategy that implements GenerateIDToken,
	// which *oauth2.DefaultJWTStrategy alone does not implement.
	keyGetter := func(_ context.Context) (any, error) {
		return key, nil
	}
	hmacStrategy := compose.NewOAuth2HMACStrategy(fositeConfig)
	commonStrategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, fositeConfig),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fositeConfig),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}

	// fosite v0.49 has no device-code compose factory; omit it.
	// Device flow is handled externally via Server.ApproveDevice / DenyDevice.
	provider := compose.Compose(
		fositeConfig,
		ad,
		commonStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2PKCEFactory,
	)

	srv := &Server{
		provider:  provider,
		config:    cfg,
		adapter:   ad,
		sessions:  sessions,
		consent:   consent,
		userInfo:  userInfo,
		users:     users,
		devices:   devices,
		publicKey: &key.PublicKey,
	}
	for _, opt := range opts {
		opt(srv)
	}
	return srv, nil
}

// ApproveDevice records user approval for the given user_code.
func (s *Server) ApproveDevice(ctx context.Context, userCode string, user sanctum.User) error {
	dc, err := s.devices.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return fmt.Errorf("passport: approve device: %w", err)
	}
	dc.Status = DeviceStatusApproved
	dc.UserID = user.GetID()
	return s.devices.UpdateDeviceCode(ctx, dc)
}

// DenyDevice records that the device authorization request for userCode was denied.
func (s *Server) DenyDevice(ctx context.Context, userCode string) error {
	dc, err := s.devices.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return fmt.Errorf("passport: deny device: %w", err)
	}
	dc.Status = DeviceStatusDenied
	return s.devices.UpdateDeviceCode(ctx, dc)
}

func applyDefaults(cfg *Config) {
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = defaultAccessTokenTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if cfg.AuthCodeTTL == 0 {
		cfg.AuthCodeTTL = defaultAuthCodeTTL
	}
	if cfg.DeviceCodeTTL == 0 {
		cfg.DeviceCodeTTL = defaultDeviceCodeTTL
	}
	if cfg.DeviceInterval == 0 {
		cfg.DeviceInterval = 5
	}
}

const (
	defaultAccessTokenTTL  = 1 * 60 * 60 * 1e9
	defaultRefreshTokenTTL = 30 * 24 * 3600 * 1e9
	defaultAuthCodeTTL     = 10 * 60 * 1e9
	defaultDeviceCodeTTL   = 5 * 60 * 1e9
)
