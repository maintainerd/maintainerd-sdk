// Package runtime is the SDK client for maintainerd-docker's RuntimeService.
// It exposes SDK-native types so callers never touch the generated protobuf.
package runtime

import (
	"context"

	"google.golang.org/grpc"

	runtimev1 "github.com/maintainerd/docker/gen/maintainerd/runtime/v1"
)

// Client talks to a runtime provider (maintainerd-docker or a future k8s one).
type Client struct {
	c runtimev1.RuntimeServiceClient
}

// New wraps an existing gRPC connection (dialed by sdk.New with credentials).
func New(conn *grpc.ClientConn) *Client {
	return &Client{c: runtimev1.NewRuntimeServiceClient(conn)}
}

// Spec is the desired container workload.
type Spec struct {
	Image  string
	Name   string
	Cmd    []string
	Env    map[string]string
	Labels map[string]string
}

// Workload is the observed state of a container.
type Workload struct {
	ID       string
	Name     string
	Image    string
	State    string
	Running  bool
	ExitCode int
	Error    string
}

func (c *Client) Ping(ctx context.Context) error {
	_, err := c.c.Ping(ctx, &runtimev1.PingRequest{})
	return err
}

func (c *Client) Pull(ctx context.Context, image string) error {
	_, err := c.c.Pull(ctx, &runtimev1.PullRequest{Image: image})
	return err
}

// Run creates and starts a workload, returning its id.
func (c *Client) Run(ctx context.Context, s Spec) (string, error) {
	resp, err := c.c.Run(ctx, &runtimev1.RunRequest{Spec: &runtimev1.WorkloadSpec{
		Image:  s.Image,
		Name:   s.Name,
		Cmd:    s.Cmd,
		Env:    s.Env,
		Labels: s.Labels,
	}})
	if err != nil {
		return "", err
	}
	return resp.GetHandle().GetId(), nil
}

func (c *Client) Stop(ctx context.Context, id string) error {
	_, err := c.c.Stop(ctx, &runtimev1.StopRequest{Handle: &runtimev1.WorkloadHandle{Id: id}})
	return err
}

func (c *Client) Remove(ctx context.Context, id string) error {
	_, err := c.c.Remove(ctx, &runtimev1.RemoveRequest{Handle: &runtimev1.WorkloadHandle{Id: id}})
	return err
}

func (c *Client) Status(ctx context.Context, id string) (Workload, error) {
	resp, err := c.c.Status(ctx, &runtimev1.StatusRequest{Handle: &runtimev1.WorkloadHandle{Id: id}})
	if err != nil {
		return Workload{}, err
	}
	return toWorkload(resp.GetStatus()), nil
}

func (c *Client) List(ctx context.Context) ([]Workload, error) {
	resp, err := c.c.List(ctx, &runtimev1.ListRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]Workload, 0, len(resp.GetWorkloads()))
	for _, w := range resp.GetWorkloads() {
		out = append(out, toWorkload(w))
	}
	return out, nil
}

func toWorkload(w *runtimev1.WorkloadStatus) Workload {
	if w == nil {
		return Workload{}
	}
	return Workload{
		ID:       w.GetId(),
		Name:     w.GetName(),
		Image:    w.GetImage(),
		State:    w.GetState(),
		Running:  w.GetRunning(),
		ExitCode: int(w.GetExitCode()),
		Error:    w.GetError(),
	}
}
