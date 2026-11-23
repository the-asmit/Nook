package config

import "fmt"

// Environment names the deployment environment a binary runs in. It
// switches development conveniences on and production safeguards (such as
// mandatory TLS) on or off.
type Environment string

// The supported environments.
const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// Validate checks that e is one of the supported environments.
func (e Environment) Validate() error {
	switch e {
	case Development, Staging, Production:
		return nil
	default:
		return fmt.Errorf("must be one of %q, %q or %q, got %q", Development, Staging, Production, string(e))
	}
}

// IsDevelopment reports whether e is the local development environment.
func (e Environment) IsDevelopment() bool {
	return e == Development
}

// RequiresTLS reports whether every network connection must use TLS.
// Only local development may talk plaintext, and only to localhost-bound
// services.
func (e Environment) RequiresTLS() bool {
	return e != Development
}
