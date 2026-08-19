// Package core is the SDK client for maintainerd-core's AgentGateway (the agent
// control-plane seam). SDK-native types; no protobuf leaks to callers.
package core

import (
	"context"

	"google.golang.org/grpc"

	corev1 "github.com/maintainerd/core/gen/maintainerd/core/v1"
)

// Client talks to Core's AgentGateway.
type Client struct {
	c corev1.AgentGatewayServiceClient
}

func New(conn *grpc.ClientConn) *Client {
	return &Client{c: corev1.NewAgentGatewayServiceClient(conn)}
}

// WorkItem is a resource that needs reconciling.
type WorkItem struct {
	ResourceUUID string
	Kind         string
	Name         string
	SpecJSON     string
	Generation   int64
}

// StatusReport is the observed state to report back for a resource.
type StatusReport struct {
	ResourceUUID       string
	State              string
	StatusJSON         string
	ObservedGeneration int64
}

func (c *Client) Register(ctx context.Context, agentUUID, version string, capabilities []string) error {
	_, err := c.c.Register(ctx, &corev1.RegisterRequest{AgentUuid: agentUUID, Version: version, Capabilities: capabilities})
	return err
}

func (c *Client) Heartbeat(ctx context.Context, agentUUID string) error {
	_, err := c.c.Heartbeat(ctx, &corev1.HeartbeatRequest{AgentUuid: agentUUID})
	return err
}

func (c *Client) PullWork(ctx context.Context, agentUUID string, max int32) ([]WorkItem, error) {
	resp, err := c.c.PullWork(ctx, &corev1.PullWorkRequest{AgentUuid: agentUUID, MaxItems: max})
	if err != nil {
		return nil, err
	}
	out := make([]WorkItem, 0, len(resp.GetItems()))
	for _, it := range resp.GetItems() {
		out = append(out, WorkItem{
			ResourceUUID: it.GetResourceUuid(),
			Kind:         it.GetKind(),
			Name:         it.GetName(),
			SpecJSON:     it.GetSpecJson(),
			Generation:   it.GetGeneration(),
		})
	}
	return out, nil
}

func (c *Client) ReportStatus(ctx context.Context, agentUUID string, reports []StatusReport) (int32, error) {
	protoReports := make([]*corev1.StatusReport, 0, len(reports))
	for _, r := range reports {
		protoReports = append(protoReports, &corev1.StatusReport{
			ResourceUuid:       r.ResourceUUID,
			State:              r.State,
			StatusJson:         r.StatusJSON,
			ObservedGeneration: r.ObservedGeneration,
		})
	}
	resp, err := c.c.ReportStatus(ctx, &corev1.ReportStatusRequest{AgentUuid: agentUUID, Reports: protoReports})
	if err != nil {
		return 0, err
	}
	return resp.GetAccepted(), nil
}
