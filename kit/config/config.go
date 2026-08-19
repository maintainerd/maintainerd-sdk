// Package config provides the env-based config helpers and the Base config that
// every maintainerd service shares, so services stop re-implementing them.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// GetEnv returns the env var or def when unset/empty.
func GetEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// GetDuration parses a duration env var (Go duration string or bare seconds).
func GetDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	return def
}

// NormalizePort ensures a listen address has a leading colon (":8080").
func NormalizePort(p string) string {
	if p == "" {
		return p
	}
	if !strings.HasPrefix(p, ":") {
		return ":" + p
	}
	return p
}

// Base is the configuration every maintainerd service carries.
type Base struct {
	AppEnv         string // "development" or "production"
	LogLevel       string // debug|info|warn|error
	SecretProvider string // SECRET_PROVIDER (default "env")
}

// LoadBase reads the shared config from the environment.
func LoadBase() Base {
	return Base{
		AppEnv:         GetEnv("APP_ENV", "development"),
		LogLevel:       GetEnv("LOG_LEVEL", "info"),
		SecretProvider: GetEnv("SECRET_PROVIDER", "env"),
	}
}
