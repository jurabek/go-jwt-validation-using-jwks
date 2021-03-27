package jwt

import "net/http"

// JWKHttpClient is implementation of jwk.HTTPClient
type JWKHttpClient struct {
	HttpClient *http.Client
}

// Get returns jwk response
func (c *JWKHttpClient) Do(req *http.Request) (*http.Response, error) {
	var client *http.Client
	if c.HttpClient != nil {
		client = c.HttpClient
	} else {
		client = http.DefaultClient
	}
	return client.Do(req)
}
