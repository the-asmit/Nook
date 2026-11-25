// Package rollout releases built images: it places a deployment's
// instance on a node (through the scheduler), has the node's agent start
// it, switches the app over once the new instance is healthy, and stops
// the previous instance after a drain period. A release that fails leaves
// the previous version serving. It also keeps live deployments in their
// desired state (stopped or running), reconciles a node's containers when
// its agent reconnects, and streams app logs from agents.
//
// Rollouts are driven by the build dispatcher's per-deployment owner
// loop: Step is called for deployments that are built, deploying or live,
// and every change is a compare-and-set in Postgres, so racing owners and
// repeated reports cannot release a deployment twice.
package rollout

import (
	"errors"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds rollout timings and log-streaming limits.
type Config struct {
	// Drain is how long the previous instance keeps serving after the new
	// one is live, so requests in flight finish.
	Drain time.Duration `env:"NOOK_ROLLOUT_DRAIN" envDefault:"10s"`
	// PullTimeout is how long a node may take to pull an image, before the
	// app's startup timeout starts counting.
	PullTimeout time.Duration `env:"NOOK_ROLLOUT_PULL_TIMEOUT" envDefault:"10m"`
	// LogMaxBytes caps the output one `nook logs` request receives.
	LogMaxBytes int64 `env:"NOOK_APP_LOGS_MAX_BYTES" envDefault:"10485760"`
	// LogMaxDuration caps how long `nook logs --follow` streams.
	LogMaxDuration time.Duration `env:"NOOK_APP_LOGS_MAX_DURATION" envDefault:"1h"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckDuration("NOOK_ROLLOUT_DRAIN", c.Drain, 0, 10*time.Minute),
		config.CheckDuration("NOOK_ROLLOUT_PULL_TIMEOUT", c.PullTimeout, 10*time.Second, time.Hour),
		config.CheckRange("NOOK_APP_LOGS_MAX_BYTES", c.LogMaxBytes, 64<<10, 1<<30),
		config.CheckDuration("NOOK_APP_LOGS_MAX_DURATION", c.LogMaxDuration, 10*time.Second, 24*time.Hour),
	)
}

// Fixed timings.
const (
	// dispatchTimeout bounds handing a command to an agent (agents accept
	// instance commands at once and report the outcome later).
	dispatchTimeout = 15 * time.Second
	// lostGrace is extra time after the pull and startup timeouts before
	// an instance whose agent never reported is considered lost.
	lostGrace = time.Minute
	// maxStartupLog bounds the kept output of a failed instance.
	maxStartupLog = 64 << 10
	// maxMessage bounds a user-facing message from an agent.
	maxMessage = 500
)
