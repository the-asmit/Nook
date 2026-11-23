// Package config loads typed configuration from environment variables.
//
// Each platform package owns the configuration struct for the thing it
// builds (postgres.Config, redis.Config, ...). A binary composes those into
// one struct and calls Load, which parses the environment, resolves *_FILE
// secrets and runs validation so the process fails fast on bad input.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"
)

// Validator is implemented by configuration structs that check their own
// invariants after parsing.
type Validator interface {
	Validate() error
}

// Load parses environ into a new T, then validates it.
//
// For every variable NOOK_X_FILE present in environ, the trimmed contents of
// that file become the value of NOOK_X. This lets secrets come from mounted
// files (Docker/Kubernetes secrets) instead of the process environment.
func Load[T any, P interface {
	*T
	Validator
}](environ map[string]string) (T, error) {
	var cfg T
	resolved, err := resolveFileVariables(environ)
	if err != nil {
		return cfg, err
	}
	if err := env.ParseWithOptions(&cfg, env.Options{Environment: resolved}); err != nil {
		return cfg, fmt.Errorf("parse environment: %w", err)
	}
	if err := P(&cfg).Validate(); err != nil {
		return cfg, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}

// OSEnviron returns the current process environment as a map for Load.
func OSEnviron() map[string]string {
	return env.ToMap(os.Environ())
}

// Problems flattens an error built with errors.Join (or a parser's
// aggregate error) into one message per problem, for readable fail-fast
// output.
func Problems(err error) []string {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var out []string
		for _, e := range joined.Unwrap() {
			out = append(out, Problems(e)...)
		}
		return out
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		inner := Problems(wrapped)
		if len(inner) > 1 {
			return inner
		}
	}
	return []string{strings.TrimSpace(err.Error())}
}
