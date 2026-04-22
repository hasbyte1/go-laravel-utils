package passport

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
)

// RegisterRoutes mounts all handlers onto mux at the default paths.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /oauth/authorize", s.HandleAuthorize())
	mux.Handle("POST /oauth/token", s.HandleToken())
	mux.Handle("POST /oauth/revoke", s.HandleRevoke())
	mux.Handle("/oauth/userinfo", s.HandleUserInfo())
	mux.Handle("POST /oauth/device/code", s.HandleDeviceAuthorization())
	mux.Handle("GET /.well-known/openid-configuration", s.HandleDiscovery())
	mux.Handle("GET /.well-known/jwks.json", s.HandleJWKS())
}

// HandleAuthorize handles GET /oauth/authorize.
func (s *Server) HandleAuthorize() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ar, err := s.provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			s.provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		user, err := s.sessions.GetUser(ctx, r)
		if err != nil {
			s.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithDebug(err.Error()))
			return
		}
		if user == nil {
			returnURL := r.URL.String()
			http.Redirect(w, r, s.config.LoginURL+"?return="+url.QueryEscape(returnURL), http.StatusFound)
			return
		}

		scopes := ar.GetRequestedScopes()
		granted, err := s.consent.IsConsentGranted(ctx, user.GetID(), ar.GetClient().GetID(), scopes)
		if err != nil {
			s.provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithDebug(err.Error()))
			return
		}
		if !granted {
			returnURL := r.URL.String()
			consentURL := fmt.Sprintf("%s?client_id=%s&scopes=%s&return=%s",
				s.config.ConsentURL,
				url.QueryEscape(ar.GetClient().GetID()),
				url.QueryEscape(strings.Join(scopes, " ")),
				url.QueryEscape(returnURL),
			)
			http.Redirect(w, r, consentURL, http.StatusFound)
			return
		}

		for _, scope := range scopes {
			ar.GrantScope(scope)
		}
		sess := newSession(user.GetID())
		sess.Claims.Nonce = r.URL.Query().Get("nonce")

		response, err := s.provider.NewAuthorizeResponse(ctx, ar, sess)
		if err != nil {
			s.provider.WriteAuthorizeError(ctx, w, ar, err)
			return
		}
		s.provider.WriteAuthorizeResponse(ctx, w, ar, response)
	})
}

// HandleToken handles POST /oauth/token.
// The session must implement oauth2.JWTSessionContainer when using a JWT access
// token strategy. openid.DefaultSession does not satisfy that interface.
func (s *Server) HandleToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sess := &oauth2.JWTSession{}
		ar, err := s.provider.NewAccessRequest(ctx, r, sess)
		if err != nil {
			s.provider.WriteAccessError(ctx, w, ar, err)
			return
		}
		response, err := s.provider.NewAccessResponse(ctx, ar)
		if err != nil {
			s.provider.WriteAccessError(ctx, w, ar, err)
			return
		}
		s.provider.WriteAccessResponse(ctx, w, ar, response)
	})
}

// HandleRevoke handles POST /oauth/revoke (RFC 7009).
func (s *Server) HandleRevoke() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		err := s.provider.NewRevocationRequest(ctx, r)
		s.provider.WriteRevocationResponse(ctx, w, err)
	})
}

// HandleDeviceAuthorization handles POST /oauth/device/code (RFC 8628).
// fosite v0.49 does not ship a device-code grant factory; this endpoint
// returns 501 Not Implemented. Upgrade fosite to a version that includes
// RFC 8628 support to activate this flow.
func (s *Server) HandleDeviceAuthorization() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not_implemented","error_description":"device authorization grant requires a newer fosite version"}`,
			http.StatusNotImplemented)
	})
}

// userInfoSession is a thin adapter so that the userinfo handler can pass an
// openid.DefaultSession to IntrospectToken when the token is a JWT access token.
// fosite v0.49 IntrospectToken accepts any fosite.Session; the JWT strategy
// only requires a JWTSessionContainer on the write path (GenerateJWT), not on
// introspection, so openid.DefaultSession works here.
var _ = (*openid.DefaultSession)(nil) // ensure import is used
