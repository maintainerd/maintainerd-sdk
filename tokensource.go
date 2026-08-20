package sdk

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenResponse is the OAuth2 token-endpoint success body.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// cachedTokenSource is a Credentials that fetches an access token from an OAuth2
// token endpoint and caches it until shortly before expiry. Safe for concurrent
// use. Both client-credentials and private_key_jwt build on it.
type cachedTokenSource struct {
	mu    sync.Mutex
	token string
	exp   time.Time
	fetch func(ctx context.Context) (token string, ttl time.Duration, err error)
}

func (c *cachedTokenSource) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.exp) {
		return c.token, nil
	}
	tok, ttl, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	// Refresh a little early so a call never rides an about-to-expire token.
	skew := 30 * time.Second
	if ttl <= skew {
		skew = ttl / 2
	}
	c.token = tok
	c.exp = time.Now().Add(ttl - skew)
	return tok, nil
}

// ClientCredentialsConfig configures an OAuth2 client_credentials grant.
type ClientCredentialsConfig struct {
	TokenEndpoint string       // auth's token endpoint (from auth.Discover)
	ClientID      string       // the confidential client
	ClientSecret  string       // its secret (from the secret provider)
	Audience      string       // the API the token is minted for (optional)
	Scopes        []string     // requested scopes (optional)
	HTTPClient    *http.Client // optional
}

// ClientCredentials returns Credentials that mint a service token via the OAuth2
// client_credentials grant (client_id + secret). Use for a service that holds a
// shared secret.
func ClientCredentials(cfg ClientCredentialsConfig) (Credentials, error) {
	if cfg.TokenEndpoint == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("sdk: ClientCredentials requires TokenEndpoint, ClientID and ClientSecret")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &cachedTokenSource{fetch: func(ctx context.Context) (string, time.Duration, error) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {cfg.ClientID},
			"client_secret": {cfg.ClientSecret},
		}
		if cfg.Audience != "" {
			form.Set("audience", cfg.Audience)
		}
		if len(cfg.Scopes) > 0 {
			form.Set("scope", strings.Join(cfg.Scopes, " "))
		}
		return postToken(ctx, hc, cfg.TokenEndpoint, form)
	}}, nil
}

// PrivateKeyJWTConfig configures an RFC 7523 private_key_jwt grant — the M2M
// method core uses to operate auth. Auth holds only the public JWKS, so the
// private key here is the sole credential (a DB dump of auth can't impersonate
// the client).
type PrivateKeyJWTConfig struct {
	TokenEndpoint string       // auth's token endpoint
	ClientID      string       // the registered control client (the oauth_client_id)
	PrivateKeyPEM []byte       // the RSA private key (PKCS#1 or PKCS#8 PEM)
	KeyID         string       // kid of the public JWK registered with auth (optional)
	Audience      string       // API the resulting token is minted for (optional)
	Scopes        []string     // requested scopes (optional)
	HTTPClient    *http.Client // optional
}

// PrivateKeyJWT returns Credentials that authenticate via a signed client
// assertion (private_key_jwt). This is how core, after setup, authenticates to
// auth as its control client using the private key it saved in control_plane.
func PrivateKeyJWT(cfg PrivateKeyJWTConfig) (Credentials, error) {
	if cfg.TokenEndpoint == "" || cfg.ClientID == "" || len(cfg.PrivateKeyPEM) == 0 {
		return nil, errors.New("sdk: PrivateKeyJWT requires TokenEndpoint, ClientID and PrivateKeyPEM")
	}
	key, err := parseRSAPrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &cachedTokenSource{fetch: func(ctx context.Context) (string, time.Duration, error) {
		assertion, err := signClientAssertion(key, cfg.ClientID, cfg.TokenEndpoint, cfg.KeyID)
		if err != nil {
			return "", 0, err
		}
		form := url.Values{
			"grant_type":            {"client_credentials"},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
		}
		if cfg.Audience != "" {
			form.Set("audience", cfg.Audience)
		}
		if len(cfg.Scopes) > 0 {
			form.Set("scope", strings.Join(cfg.Scopes, " "))
		}
		return postToken(ctx, hc, cfg.TokenEndpoint, form)
	}}, nil
}

// signClientAssertion builds and signs the RFC 7523 client assertion JWT.
func signClientAssertion(key *rsa.PrivateKey, clientID, tokenEndpoint, kid string) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint, // the token endpoint is the assertion's audience
		"jti": hex.EncodeToString(jti),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	return tok.SignedString(key)
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sdk: no PEM block in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sdk: parse private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("sdk: private key is not RSA")
	}
	return key, nil
}

func postToken(ctx context.Context, hc *http.Client, endpoint string, form url.Values) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("sdk: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", 0, fmt.Errorf("sdk: decode token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		msg := tr.Error
		if tr.ErrorDesc != "" {
			msg += ": " + tr.ErrorDesc
		}
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return "", 0, fmt.Errorf("sdk: token endpoint rejected: %s", msg)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute // conservative default when the server omits expires_in
	}
	return tr.AccessToken, ttl, nil
}
