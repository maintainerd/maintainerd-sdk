// Package setup implements the one-time setup-mode / controller-registration
// pattern every attachable service uses. On first boot a service accepts setup
// calls guarded by a bootstrap token; once Core completes setup and registers as
// controller, setup locks and the endpoints stop working — exactly like Auth's
// setup mode.
package setup

import (
	"errors"
	"sync"
)

var (
	// ErrSetupComplete is returned when a setup call arrives after setup is done.
	ErrSetupComplete = errors.New("setup already complete")
	// ErrUnauthorized is returned when the bootstrap token does not match.
	ErrUnauthorized = errors.New("invalid bootstrap token")
)

// Mode guards a service's one-time setup window.
type Mode struct {
	mu         sync.RWMutex
	token      string
	done       bool
	controller string
}

// New creates a setup Mode gated by bootstrapToken. An empty token means setup
// is open (dev only) until Complete is called.
func New(bootstrapToken string) *Mode {
	return &Mode{token: bootstrapToken}
}

// Authorize checks a setup request: allowed only while setup is open and the
// token matches. Call this at the top of every setup endpoint.
func (m *Mode) Authorize(token string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.done {
		return ErrSetupComplete
	}
	if m.token != "" && token != m.token {
		return ErrUnauthorized
	}
	return nil
}

// Complete records the controller and permanently locks setup. Idempotent-safe:
// a second call after completion returns ErrSetupComplete.
func (m *Mode) Complete(controller string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done {
		return ErrSetupComplete
	}
	m.done = true
	m.controller = controller
	return nil
}

// IsComplete reports whether setup has finished.
func (m *Mode) IsComplete() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.done
}

// Controller returns the identity that completed setup (empty until complete).
func (m *Mode) Controller() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.controller
}
