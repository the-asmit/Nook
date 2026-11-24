// Package nodes keeps track of worker nodes: joining with tokens, their
// certificates, heartbeats, health states and the failure detector that
// moves them between states.
package nodes

import (
	"errors"
	"fmt"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// suspectMisses is how many heartbeat intervals may pass without a
// heartbeat before a node is suspect.
const suspectMisses = 3

// Config holds node timings.
type Config struct {
	// HeartbeatInterval is how often agents send heartbeats.
	HeartbeatInterval time.Duration `env:"NOOK_HEARTBEAT_INTERVAL" envDefault:"5s"`
	// DeadAfter is how long without heartbeats before a node is dead.
	DeadAfter time.Duration `env:"NOOK_NODE_DEAD_AFTER" envDefault:"30s"`
	// PersistInterval throttles writing heartbeats to Postgres; the latest
	// one always lives in Redis.
	PersistInterval time.Duration `env:"NOOK_HEARTBEAT_PERSIST_INTERVAL" envDefault:"30s"`
	// DetectorInterval is how often the leader evaluates node health.
	DetectorInterval time.Duration `env:"NOOK_FAILURE_DETECTOR_INTERVAL" envDefault:"1s"`
	// CertTTL is the lifetime of node client certificates.
	CertTTL time.Duration `env:"NOOK_NODE_CERT_TTL" envDefault:"168h"`
	// JoinTokenTTL is the default lifetime of new join tokens.
	JoinTokenTTL time.Duration `env:"NOOK_JOIN_TOKEN_TTL" envDefault:"1h"`
	// CommandTimeout is the default time an agent gets to answer a command.
	CommandTimeout time.Duration `env:"NOOK_NODE_COMMAND_TIMEOUT" envDefault:"15s"`
}

// MaxJoinTokenTTL caps join token lifetimes: they are bearer secrets.
const MaxJoinTokenTTL = 7 * 24 * time.Hour

// SuspectAfter is how long without heartbeats before a node is suspect.
func (c *Config) SuspectAfter() time.Duration {
	return suspectMisses * c.HeartbeatInterval
}

// Validate checks the timings and their relations.
func (c *Config) Validate() error {
	errs := []error{
		config.CheckDuration("NOOK_HEARTBEAT_INTERVAL", c.HeartbeatInterval, time.Second, time.Minute),
		config.CheckDuration("NOOK_NODE_DEAD_AFTER", c.DeadAfter, 3*time.Second, time.Hour),
		config.CheckDuration("NOOK_HEARTBEAT_PERSIST_INTERVAL", c.PersistInterval, time.Second, time.Hour),
		config.CheckDuration("NOOK_FAILURE_DETECTOR_INTERVAL", c.DetectorInterval, 100*time.Millisecond, time.Minute),
		config.CheckDuration("NOOK_NODE_CERT_TTL", c.CertTTL, time.Hour, 90*24*time.Hour),
		config.CheckDuration("NOOK_JOIN_TOKEN_TTL", c.JoinTokenTTL, time.Minute, MaxJoinTokenTTL),
		config.CheckDuration("NOOK_NODE_COMMAND_TIMEOUT", c.CommandTimeout, time.Second, 5*time.Minute),
	}
	if c.DeadAfter <= c.SuspectAfter() {
		errs = append(errs, fmt.Errorf("NOOK_NODE_DEAD_AFTER (%s) must be longer than %d heartbeat intervals (%s)",
			c.DeadAfter, suspectMisses, c.SuspectAfter()))
	}
	if c.DetectorInterval > c.HeartbeatInterval {
		errs = append(errs, errors.New("NOOK_FAILURE_DETECTOR_INTERVAL must not exceed NOOK_HEARTBEAT_INTERVAL"))
	}
	return errors.Join(errs...)
}
