// Package passport provides a Laravel Passport-inspired OAuth2 and OpenID Connect
// authorization server for Go. It wraps ory/fosite as an internal implementation
// detail — consumers never import fosite directly.
//
// Quick start:
//
//	key, _ := rsa.GenerateKey(rand.Reader, 2048)
//	store := inmemory.New()
//	store.AddClient(&passport.OAuthClient{
//	    ID: "my-app", SecretHash: "<bcrypt>",
//	    GrantTypes: []string{"authorization_code", "refresh_token"},
//	    Scopes: []string{"openid", "profile"}, Public: true,
//	})
//	srv, _ := passport.NewServer(passport.DefaultConfig("https://auth.example.com"),
//	    store, store, store, store, store,
//	    sessions, consent, userInfo, users, key)
//	mux := http.NewServeMux()
//	srv.RegisterRoutes(mux)
package passport
