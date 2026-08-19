// Package secret is the SDK client for maintainerd-secret's SecretService.
// SDK-native types; no protobuf leaks to callers.
package secret

import (
	"context"

	"google.golang.org/grpc"

	secretv1 "github.com/maintainerd/secret/gen/maintainerd/secret/v1"
)

// Client talks to a maintainerd-secret store.
type Client struct {
	c secretv1.SecretServiceClient
}

func New(conn *grpc.ClientConn) *Client {
	return &Client{c: secretv1.NewSecretServiceClient(conn)}
}

// Ping reports reachability and whether the store has completed setup.
func (c *Client) Ping(ctx context.Context) (setupComplete bool, err error) {
	resp, err := c.c.Ping(ctx, &secretv1.PingRequest{})
	if err != nil {
		return false, err
	}
	return resp.GetSetupComplete(), nil
}

// Setup registers a controller one time (used by Core during bootstrap).
func (c *Client) Setup(ctx context.Context, bootstrapToken, controller string) error {
	_, err := c.c.Setup(ctx, &secretv1.SetupRequest{BootstrapToken: bootstrapToken, Controller: controller})
	return err
}

func (c *Client) Put(ctx context.Context, key string, value []byte) error {
	_, err := c.c.Put(ctx, &secretv1.PutRequest{Key: key, Value: value})
	return err
}

func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := c.c.Get(ctx, &secretv1.GetRequest{Key: key})
	if err != nil {
		return nil, err
	}
	return resp.GetValue(), nil
}

func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	resp, err := c.c.List(ctx, &secretv1.ListRequest{Prefix: prefix})
	if err != nil {
		return nil, err
	}
	return resp.GetKeys(), nil
}

func (c *Client) Delete(ctx context.Context, key string) error {
	_, err := c.c.Delete(ctx, &secretv1.DeleteRequest{Key: key})
	return err
}
