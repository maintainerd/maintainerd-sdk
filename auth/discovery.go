package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider is the subset of OIDC discovery metadata callers need to talk to
// maintainerd-auth: where to send users to log in, where to exchange codes /
// mint service tokens, and where to fetch the verification keys.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Discover fetches the OIDC discovery document from an issuer base URL
// (`{issuer}/.well-known/openid-configuration`) so services and consoles never
// hardcode auth's endpoints — they resolve them from the issuer.
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (*Provider, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("auth: issuer is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: discover %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: discover %s: unexpected status %d", url, resp.StatusCode)
	}
	var p Provider
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("auth: decode discovery: %w", err)
	}
	return &p, nil
}
