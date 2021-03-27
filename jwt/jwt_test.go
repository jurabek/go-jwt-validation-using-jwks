package jwt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockedJWK mocked client for testing
type mockedJWK struct {
	mock.Mock
}

func (c *mockedJWK) Do(req *http.Request) (*http.Response, error) {
	args := c.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

// openssl rsa -in app.rsa -pubout > app.rsa.pub
// openssl genrsa -out app.rsa keysize
func generateKeys() *rsa.PrivateKey {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}

	return privatekey
}

func privateKeyPem(pr *rsa.PrivateKey) []byte {
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(pr)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(privateKeyBlock)
}

func publicKeyPem(pb *rsa.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pb)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(publicKeyBlock)
}

func getJWKSResponse(pk []byte, skipKid bool) []byte {
	verifyKey, _ := jwt.ParseRSAPublicKeyFromPEM(pk)
	key, _ := jwk.New(verifyKey)
	publicKey, _ := key.(jwk.RSAPublicKey)
	if !skipKid {
		_ = publicKey.Set("kid", "1234567890kid")
	}

	set := jwk.NewSet()
	set.Add(publicKey)

	keysResponse, _ := json.Marshal(set)
	return keysResponse
}

func createTestJwtToken(prk []byte, audience string, issuer string) (string, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Audience:  audience,
		Issuer:    issuer,
	}
	signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(prk)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "1234567890kid"
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func TestJwt(t *testing.T) {

	key := generateKeys()
	prkPem := privateKeyPem(key)
	pkPem := publicKeyPem(&key.PublicKey)

	token, _ := createTestJwtToken(prkPem, "menu-api", "restaurant-api")
	response := http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewBuffer(getJWKSResponse(pkPem, false))),
		Header:     make(http.Header),
	}
	ctx := context.TODO()
	jwkMockHTTPClient := mockedJWK{}

	url := "http://localhost/.well-known/openid-configuration/jwks"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	jwkMockHTTPClient.On("Do", req).Return(&response, nil)

	jwtVerifier := JwtTokenVerifier{
		HTTPClient: &jwkMockHTTPClient,
		JWKSUri:    "http://localhost/.well-known/openid-configuration/jwks",
	}

	t.Run("given valid token ValidateToken should be valid", func(t *testing.T) {
		result, err := jwtVerifier.ValidateToken(ctx, token)
		assert.True(t, result)
		assert.Nil(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("given invalid signing method validate should not pass", func(t *testing.T) {
		invalidToken := jwt.New(jwt.SigningMethodHS256)
		tokenString, _ := invalidToken.SignedString([]byte("123"))

		result, err := jwtVerifier.ValidateToken(ctx, tokenString)

		assert.Empty(t, result)
		assert.NotEmpty(t, err)
		assert.Equal(t, "unexpected signing method: HS256", err.Error())
	})

	t.Run("given wrong jwks url validate should not pass", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/wrong", nil)
		jwkMockHTTPClient.On("Do", req).Return(&response, fmt.Errorf("connection error")).Once()
		jwtVerifierWithWrongJwksURL := JwtTokenVerifier{
			HTTPClient: &jwkMockHTTPClient,
			JWKSUri:    "http://localhost/wrong",
		}

		result, err := jwtVerifierWithWrongJwksURL.ValidateToken(ctx, token)

		assert.Empty(t, result)
		assert.NotEmpty(t, err)
		assert.Equal(t, "failed to fetch remote JWK: connection error", err.Error())
	})

	t.Run("given empty kid response validate should not find key", func(t *testing.T) {
		wrongResponse := http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBuffer(getJWKSResponse(pkPem, true))),
			Header:     make(http.Header),
		}

		mock := &mockedJWK{}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/.well-known/openid-configuration/jwks", nil)
		mock.On("Do", req).Return(&wrongResponse, nil)

		newJwtVerifier := JwtTokenVerifier{
			HTTPClient: mock,
			JWKSUri:    "http://localhost/.well-known/openid-configuration/jwks",
		}

		result, err := newJwtVerifier.ValidateToken(ctx, token)

		assert.Empty(t, result)
		assert.NotEmpty(t, err)
		assert.Equal(t, "unable to find key", err.Error())
	})

	t.Run("claims test", func(t *testing.T) {
		claimsToValidate := map[string]interface{}{}
		claimsToValidate[""] = nil
	})
}
