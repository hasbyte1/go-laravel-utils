package sanctum

import (
	"encoding/json"
	"net/http"
)

// Authenticate is a net/http-compatible middleware that authenticates every incoming
// request using the provided [Guard]. On success it injects the [AuthContext] into
// the request context and calls the next handler. On failure it writes a JSON error
// response and stops the chain.
//
// Use [AuthContextFromRequest] in downstream handlers to retrieve the auth result.
func Authenticate(g *Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ac, err := g.Authenticate(r)
			if err != nil {
				writeJSONError(w, authErrStatus(err), err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(WithAuthContext(r.Context(), ac)))
		})
	}
}

// RequireAbilities is a net/http-compatible middleware that enforces that the
// authenticated token has ALL of the specified abilities (AND logic).
//
// Must be applied after [Authenticate]. Session-authenticated (SPA) requests are
// not subject to ability checks — they are always granted full access.
// Returns 403 Forbidden when the ability check fails.
func RequireAbilities(abilities ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ac := AuthContextFromRequest(r)
			if ac == nil {
				writeJSONError(w, http.StatusUnauthorized, ErrUnauthorized.Error())
				return
			}
			if !ac.IsSessionAuth {
				if ac.Token == nil || !CanAll(ac.Token.Abilities, abilities) {
					writeJSONError(w, http.StatusForbidden, ErrForbidden.Error())
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyAbility is a net/http-compatible middleware that enforces that the
// authenticated token has AT LEAST ONE of the specified abilities (OR logic).
//
// Must be applied after [Authenticate]. Session-authenticated (SPA) requests are
// always granted access. Returns 403 Forbidden when the ability check fails.
func RequireAnyAbility(abilities ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ac := AuthContextFromRequest(r)
			if ac == nil {
				writeJSONError(w, http.StatusUnauthorized, ErrUnauthorized.Error())
				return
			}
			if !ac.IsSessionAuth {
				if ac.Token == nil || !CanAny(ac.Token.Abilities, abilities) {
					writeJSONError(w, http.StatusForbidden, ErrForbidden.Error())
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func authErrStatus(err error) int {
	switch err {
	case ErrForbidden, ErrCSRFMismatch, ErrInvalidCSRFToken:
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}
