// Package auth is the SDK's identity component: it validates maintainerd
// system-Auth (IAM) tokens so any service or external app can enforce access
// the AWS-IAM way — the caller attaches a token (SDK Credentials), the callee
// verifies it here. Verification is a pure JWKS/JWT check; it needs only the
// Auth service's public JWKS URL, not a dependency on the Auth codebase.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Claims is the validated identity of a caller.
type Claims struct {
	Subject string
	Tenant  string
	Scopes  []string
	Raw     jwt.MapClaims
}

// Verifier validates JWTs against a JWKS endpoint (Auth's public keys), with
// automatic key rotation handled by the JWKS cache.
type Verifier struct {
	jwks     keyfunc.Keyfunc
	issuer   string
	audience string
}

// NewVerifier builds a Verifier that fetches and caches Auth's JWKS. issuer and
// audience are optional extra checks ("" to skip).
func NewVerifier(ctx context.Context, jwksURL, issuer, audience string) (*Verifier, error) {
	if jwksURL == "" {
		return nil, errors.New("auth: jwksURL is required")
	}
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, err
	}
	return &Verifier{jwks: jwks, issuer: issuer, audience: audience}, nil
}

// Verify validates a bearer token and returns its claims.
func (v *Verifier) Verify(token string) (*Claims, error) {
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256", "ES256"})}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}
	parsed, err := jwt.Parse(token, v.jwks.Keyfunc, opts...)
	if err != nil {
		return nil, err
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("auth: invalid token")
	}
	c := &Claims{Raw: mc}
	if sub, _ := mc["sub"].(string); sub != "" {
		c.Subject = sub
	}
	if t, _ := mc["tenant"].(string); t != "" {
		c.Tenant = t
	}
	if scope, _ := mc["scope"].(string); scope != "" {
		c.Scopes = strings.Fields(scope)
	}
	return c, nil
}

type ctxKey struct{}

// FromContext returns the Claims placed by Middleware, if any.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// Middleware is an HTTP guard: it requires a valid system-Auth token and puts
// the Claims in the request context. This is the PEP — the enforcement point
// that makes "attached services are governed by system Auth (IAM)" real.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r.Header.Get("Authorization"))
		if token == "" {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(token)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
	})
}

func bearer(header string) string {
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}
