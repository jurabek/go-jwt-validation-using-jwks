package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

// TokenVerifier provides for token validation
type TokenVerifier interface {
	ValidateToken(bearerToken string) (bool, error)
}

// JwtTokenVerifier provides oidc server information
type JwtTokenVerifier struct {
	HTTPClient       jwk.HTTPClient
	JWKSUri          string
	ClaimsToValidate map[string]interface{}
}

func (j *JwtTokenVerifier) Parse(ctx context.Context, bearerToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		if err, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println(err)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		set, err := j.fetchAndCacheJWKS(ctx)
		if err != nil {
			return nil, err
		}

		keyID, _ := token.Header["kid"].(string)
		if key, ok := set.LookupKeyID(keyID); ok {
			var result rsa.PublicKey
			err := key.Raw(&result)
			if err != nil {
				return nil, err
			}
			return &result, nil
		}

		return nil, errors.New("unable to find key")
	})

	return token, err
}

// ValidateToken validates claims with given token
func (j *JwtTokenVerifier) ValidateToken(ctx context.Context, bearerToken string) (bool, error) {
	token, err := j.Parse(ctx, bearerToken)
	if err != nil {
		return false, err
	}

	return j.validateTokenByClaims(token)
}

func (j *JwtTokenVerifier) validateTokenByClaims(token *jwt.Token) (bool, error) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		for k, v := range j.ClaimsToValidate {
			claim := claims[k]
			switch reflect.TypeOf(claim).Kind() {
			case reflect.String:
				if claim != v {
					return false, fmt.Errorf("claims validate failed, invalid claim: %v", k)
				}
			case reflect.Slice:
				var itemFound bool
				for _, c := range claim.([]interface{}) {
					if c == v {
						itemFound = true
						break
					}
				}
				if !itemFound {
					return false, fmt.Errorf("claims validate failed, invalid claim: %v", k)
				}
			}
		}
		return true, nil
	}

	return false, fmt.Errorf("invalid token")
}

func (j *JwtTokenVerifier) fetchAndCacheJWKS(ctx context.Context) (jwk.Set, error) {
	response, err := jwk.Fetch(ctx, j.JWKSUri, jwk.WithHTTPClient(j.HTTPClient))
	if err != nil {
		return nil, err
	}
	return response, nil
}
