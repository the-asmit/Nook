package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds session lifetimes.
type Config struct {
	// SessionIdleTimeout ends a session after this long without requests.
	SessionIdleTimeout time.Duration `env:"NOOK_SESSION_IDLE_TIMEOUT" envDefault:"24h"`
	// SessionAbsoluteTimeout ends a session this long after sign-in, however
	// active it is, so a stolen cookie cannot be used forever.
	SessionAbsoluteTimeout time.Duration `env:"NOOK_SESSION_ABSOLUTE_TIMEOUT" envDefault:"168h"`
}

// Validate checks the lifetimes.
func (c *Config) Validate() error {
	errs := []error{
		config.CheckDuration("NOOK_SESSION_IDLE_TIMEOUT", c.SessionIdleTimeout, 5*time.Minute, 30*24*time.Hour),
		config.CheckDuration("NOOK_SESSION_ABSOLUTE_TIMEOUT", c.SessionAbsoluteTimeout, 5*time.Minute, 90*24*time.Hour),
	}
	if c.SessionIdleTimeout > c.SessionAbsoluteTimeout {
		errs = append(errs, fmt.Errorf("NOOK_SESSION_IDLE_TIMEOUT (%s) must not exceed NOOK_SESSION_ABSOLUTE_TIMEOUT (%s)",
			c.SessionIdleTimeout, c.SessionAbsoluteTimeout))
	}
	return errors.Join(errs...)
}
