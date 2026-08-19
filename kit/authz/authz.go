// Package authz is the PEP (policy enforcement point): it requires a valid
// caller identity on requests. It is decoupled from any token library — the
// service injects a VerifyFunc (e.g. the client SDK's auth.Verifier.Verify), so
// the kit stays dependency-light while still enforcing system-Auth (IAM).
package authz

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Principal is the validated caller.
type Principal struct {
	Subject string
	Tenant  string
	Scopes  []string
}

// VerifyFunc validates a bearer token and returns its principal.
type VerifyFunc func(ctx context.Context, token string) (*Principal, error)

type ctxKey struct{}

// PrincipalFromContext returns the principal placed by the middleware.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// HTTPMiddleware enforces a valid token on HTTP requests.
func HTTPMiddleware(verify VerifyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearer(r.Header.Get("Authorization"))
			if token == "" {
				http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
				return
			}
			p, err := verify(r.Context(), token)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
		})
	}
}

// UnaryInterceptor enforces a valid token on gRPC unary calls.
func UnaryInterceptor(verify VerifyFunc) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		token := bearerFromMD(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		p, err := verify(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		return handler(context.WithValue(ctx, ctxKey{}, p), req)
	}
}

func bearer(header string) string {
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

func bearerFromMD(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	return bearer(vals[0])
}
