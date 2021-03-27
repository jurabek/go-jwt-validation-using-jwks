package middleware

import (
	"net/http"
	"strings"

	"github.com/jurabek/jwt-validation/jwt"
)

type Auth struct {
	JwtTokenVerifier jwt.JwtTokenVerifier
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization") //Grab the token from the header
		if authorizationHeader == "" {                       //Token is missing, returns with error code 403 Unauthorized
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// The token normally comes in format `Bearer {token-body}`, we will check if the retrieved token matched this requirement
		bearerToken := strings.Split(authorizationHeader, " ")
		if len(bearerToken) != 2 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ok, err := a.JwtTokenVerifier.ValidateToken(r.Context(), bearerToken[1])
		if !ok && err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
