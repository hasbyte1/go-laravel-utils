package passport

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"

	"github.com/ory/fosite"
)

// HandleUserInfo handles GET /oauth/userinfo.
func (s *Server) HandleUserInfo() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sess := newEmptySession()
		_, ar, err := s.provider.IntrospectToken(ctx, fosite.AccessTokenFromRequest(r), fosite.AccessToken, sess)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if !ar.GetGrantedScopes().Has("openid") {
			http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
			return
		}

		userID := sess.Subject
		user, err := s.users.FindByID(ctx, userID)
		if err != nil || user == nil {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}

		claims, err := s.userInfo.GetUserInfo(ctx, user, ar.GetGrantedScopes())
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		claims["sub"] = userID

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claims) //nolint:errcheck
	})
}

// HandleDiscovery handles GET /.well-known/openid-configuration.
func (s *Server) HandleDiscovery() http.Handler {
	issuer := strings.TrimRight(s.config.Issuer, "/")
	doc := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/oauth/userinfo",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "iat", "exp", "name", "email"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	body, _ := json.Marshal(doc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) //nolint:errcheck
	})
}

// HandleJWKS handles GET /.well-known/jwks.json.
func (s *Server) HandleJWKS() http.Handler {
	pub, ok := s.publicKey.(*rsa.PublicKey)
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`)) //nolint:errcheck
		})
	}
	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "default",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	body, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) //nolint:errcheck
	})
}
