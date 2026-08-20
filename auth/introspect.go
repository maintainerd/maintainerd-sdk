package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Introspection is the RFC 7662 token-introspection response. Unlike a local
// Verify (which trusts a JWT until it expires), introspection reflects
// revocation in real time — reach for it on high-value operations or for opaque
// tokens.
type Introspection struct {
	Active    bool           `json:"active"`
	Scope     string         `json:"scope"`
	ClientID  string         `json:"client_id"`
	Username  string         `json:"username"`
	TokenType string         `json:"token_type"`
	Subject   string         `json:"sub"`
	Issuer    string         `json:"iss"`
	Expiry    int64          `json:"exp"`
	IssuedAt  int64          `json:"iat"`
	Tenant    string         `json:"tenant"`
	Raw       map[string]any `json:"-"` // every claim the endpoint returned
}

// Scopes returns the space-delimited scope claim split into a slice.
func (i *Introspection) Scopes() []string {
	if i.Scope == "" {
		return nil
	}
	return strings.Fields(i.Scope)
}

// IntrospectionConfig configures an RFC 7662 introspection call. ClientID /
// ClientSecret authenticate the caller (confidential clients) via HTTP Basic.
type IntrospectionConfig struct {
	IntrospectionEndpoint string       // from auth.Discover (Provider.IntrospectionEndpoint)
	ClientID              string       // the caller's client id (optional)
	ClientSecret          string       // the caller's client secret (optional)
	HTTPClient            *http.Client // optional
}

// Introspect asks auth whether a token is active (RFC 7662).
func Introspect(ctx context.Context, token string, cfg IntrospectionConfig) (*Introspection, error) {
	if cfg.IntrospectionEndpoint == "" || token == "" {
		return nil, errors.New("auth: Introspect requires IntrospectionEndpoint and token")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cfg.ClientID != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: introspect: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: introspect: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: introspect: read body: %w", err)
	}
	var out Introspection
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("auth: introspect: decode: %w", err)
	}
	_ = json.Unmarshal(body, &out.Raw) // best-effort: keep every claim
	return &out, nil
}

// RevocationConfig configures an RFC 7009 revocation call.
type RevocationConfig struct {
	RevocationEndpoint string       // from auth.Discover (Provider.RevocationEndpoint)
	ClientID           string       // the caller's client id (optional)
	ClientSecret       string       // the caller's client secret (optional)
	HTTPClient         *http.Client // optional
}

// Revoke invalidates a token at auth (RFC 7009). tokenTypeHint is
// "access_token" or "refresh_token" ("" to omit the hint). Per the RFC a
// successful revocation (and an already-invalid token) both return 200.
func Revoke(ctx context.Context, token, tokenTypeHint string, cfg RevocationConfig) error {
	if cfg.RevocationEndpoint == "" || token == "" {
		return errors.New("auth: Revoke requires RevocationEndpoint and token")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ClientID != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("auth: revoke: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth: revoke: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// UserInfo fetches the OIDC userinfo claims for an access token from the
// userinfo endpoint (Provider.UserinfoEndpoint). The token is sent as a bearer.
func UserInfo(ctx context.Context, userinfoEndpoint, accessToken string, httpClient *http.Client) (map[string]any, error) {
	if userinfoEndpoint == "" || accessToken == "" {
		return nil, errors.New("auth: UserInfo requires userinfoEndpoint and accessToken")
	}
	hc := httpClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: userinfo: unexpected status %d", resp.StatusCode)
	}
	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("auth: userinfo: decode: %w", err)
	}
	return claims, nil
}
