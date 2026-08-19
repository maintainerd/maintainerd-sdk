package sdk

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Credentials supplies the caller's identity token for every request — the
// maintainerd analog of AWS SigV4 signing. Under the maintainerd ecosystem the
// token is a system-Auth (IAM) token; standalone, it may be a service token or
// an end-user token. Implementations must be safe for concurrent use.
type Credentials interface {
	// Token returns the bearer token to attach, or "" for an anonymous call.
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed bearer token (e.g. a service account token injected via
// the secret provider). Good enough for service-to-service calls.
type StaticToken string

func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

// Anonymous attaches no credentials — for endpoints that do not require auth
// (health, setup-mode bootstrap) or for standalone services with auth disabled.
type Anonymous struct{}

func (Anonymous) Token(context.Context) (string, error) { return "", nil }

// unaryCredsInterceptor attaches the credential token as gRPC "authorization"
// metadata on every unary call. Registered by New when Credentials is set.
func unaryCredsInterceptor(creds Credentials) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if creds != nil {
			if tok, err := creds.Token(ctx); err == nil && tok != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
			}
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
