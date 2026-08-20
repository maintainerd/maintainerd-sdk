// Package sdk is the maintainerd client SDK — the one library external apps and
// maintainerd services import to CALL maintainerd's PRODUCT services (the
// aws-sdk-go analog). It wires typed service clients (secret, and future
// services like storage), attaches identity (Credentials — the SigV4 analog),
// and provides system-Auth (IAM) token verification.
//
// It deliberately does NOT expose the control plane (core's AgentGateway, the
// docker runtime, orchestration). Those are internal wiring, not services an
// app consumes — exactly the AWS line where aws-sdk-go ships S3/DynamoDB
// clients but not AWS's internal control plane.
//
//	client, _ := sdk.New(ctx, sdk.Config{
//	    SecretAddr:  "localhost:9092",
//	    AuthJWKSURL: "https://auth.local/.well-known/jwks.json",
//	    Credentials: sdk.StaticToken(serviceToken),
//	})
//	val, _ := client.Secret.Get(ctx, "db/password")
package sdk

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/maintainerd/sdk/auth"
	"github.com/maintainerd/sdk/secret"
)

// Config configures the SDK client. Only the services whose addresses are set
// are dialed; the rest stay nil.
type Config struct {
	SecretAddr   string // maintainerd-secret SecretService (e.g. "localhost:9092")
	AuthJWKSURL  string // system-Auth JWKS URL for token verification
	AuthIssuer   string // optional issuer check
	AuthAudience string // optional audience check

	// Credentials attaches the caller's identity token to every request.
	// Defaults to Anonymous.
	Credentials Credentials

	// DialOptions are appended to the defaults — set these for TLS/mTLS in
	// production (the defaults are insecure for local/dev).
	DialOptions []grpc.DialOption
}

// Client is the aggregate SDK entrypoint. Sub-clients are nil unless their
// address (or the JWKS URL, for Auth) was configured.
type Client struct {
	Secret *secret.Client
	Auth   *auth.Verifier

	conns []*grpc.ClientConn
}

// New builds the client, dialing each configured product service and (if
// AuthJWKSURL is set) initializing the token verifier.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Credentials == nil {
		cfg.Credentials = Anonymous{}
	}
	base := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(unaryCredsInterceptor(cfg.Credentials)),
	}
	base = append(base, cfg.DialOptions...)

	cl := &Client{}
	if cfg.SecretAddr != "" {
		conn, err := grpc.NewClient(cfg.SecretAddr, base...)
		if err != nil {
			_ = cl.Close()
			return nil, err
		}
		cl.conns = append(cl.conns, conn)
		cl.Secret = secret.New(conn)
	}
	if cfg.AuthJWKSURL != "" {
		v, err := auth.NewVerifier(ctx, cfg.AuthJWKSURL, cfg.AuthIssuer, cfg.AuthAudience)
		if err != nil {
			_ = cl.Close()
			return nil, err
		}
		cl.Auth = v
	}
	return cl, nil
}

// Close releases all dialed connections.
func (c *Client) Close() error {
	for _, conn := range c.conns {
		_ = conn.Close()
	}
	return nil
}
