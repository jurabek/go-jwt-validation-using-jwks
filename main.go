package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jurabek/jwt-validation/jwt"
	"github.com/jurabek/jwt-validation/middleware"
)

func main() {

	httpClient := jwt.JWKHttpClient{}
	verifier := jwt.JwtTokenVerifier{
		JWKSUri:    "https://dev-kc4te-sm.eu.auth0.com/.well-known/jwks.json",
		HTTPClient: &httpClient,
	}

	r := mux.NewRouter()
	r.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		t := strings.Split(r.Header.Get("Authorization"), " ")[1]
		token, _ := verifier.Parse(r.Context(), t)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(token.Raw))
	})

	amw := middleware.Auth{
		JwtTokenVerifier: verifier,
	}
	r.Use(amw.Middleware)

	err := http.ListenAndServe(":3000", r)
	log.Fatal(err)
}
