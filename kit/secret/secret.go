// Package secret is the pluggable secret provider selected by SECRET_PROVIDER.
// The default is "env". maintainerd-secret and cloud providers plug in behind
// this interface — but note seed services (core/agent/docker) can only use env
// or external, never maintainerd-secret (it does not exist at their first run).
package secret

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Provider resolves secret values by key.
type Provider interface {
	Get(ctx context.Context, key string) (string, error)
}

type envProvider struct{}

func (envProvider) Get(_ context.Context, key string) (string, error) {
	if v, ok := os.LookupEnv(key); ok {
		return v, nil
	}
	return "", fmt.Errorf("secret %q not found in environment", key)
}

// New returns the provider named by SECRET_PROVIDER. Unknown or not-yet-available
// providers warn and fall back to env so the service still starts.
func New(name string) Provider {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "env":
		return envProvider{}
	default:
		slog.Warn("SECRET_PROVIDER not available; falling back to env", "provider", name)
		return envProvider{}
	}
}
