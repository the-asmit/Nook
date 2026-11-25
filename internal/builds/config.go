// Package builds turns queued deployments into images: a Redis Streams
// build queue consumed by every control-plane instance, a dispatcher that
// places each build on a node and sees it through to the end (retrying
// infrastructure failures elsewhere), the handling of build output and
// results reported by agents, live build logs for any number of
// followers on any instance, and the janitor that enforces retention.
package builds

import (
	"errors"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds build limits and timings.
type Config struct {
	// Timeout is the longest a build may run; the agent kills it after.
	Timeout time.Duration `env:"NOOK_BUILD_TIMEOUT" envDefault:"15m"`
	// MemoryMB and CPUMillicores limit each build container.
	MemoryMB      int64 `env:"NOOK_BUILD_MEMORY_MB" envDefault:"2048"`
	CPUMillicores int64 `env:"NOOK_BUILD_CPU_MILLICORES" envDefault:"2000"`
	// MaxLogBytes caps a build's log; output beyond it is dropped.
	MaxLogBytes int64 `env:"NOOK_BUILD_MAX_LOG_BYTES" envDefault:"5242880"`
	// QueueTimeout fails a deployment that found no build capacity in time.
	QueueTimeout time.Duration `env:"NOOK_BUILD_QUEUE_TIMEOUT" envDefault:"30m"`
	// MaxAttempts bounds retries after infrastructure failures.
	MaxAttempts int32 `env:"NOOK_BUILD_MAX_ATTEMPTS" envDefault:"3"`
	// ClaimTimeout is how long a job may sit unacknowledged by a silent
	// (crashed) instance before another instance reclaims it.
	ClaimTimeout time.Duration `env:"NOOK_BUILD_CLAIM_TIMEOUT" envDefault:"60s"`
	// AcceptTimeout marks a build lost if its agent never acknowledged it.
	AcceptTimeout time.Duration `env:"NOOK_BUILD_ACCEPT_TIMEOUT" envDefault:"30s"`
	// TickInterval is how often a deployment's owner re-checks it (it is
	// also woken immediately by results and cancellations).
	TickInterval time.Duration `env:"NOOK_BUILD_TICK_INTERVAL" envDefault:"2s"`
	// ImageRetention is how many built images are kept per app.
	ImageRetention int64 `env:"NOOK_IMAGE_RETENTION_COUNT" envDefault:"10"`
	// ArtifactRetention is how long source archives and build logs are kept.
	ArtifactRetention time.Duration `env:"NOOK_BUILD_ARTIFACT_RETENTION" envDefault:"720h"`
	// JanitorInterval is how often the leader enforces retention.
	JanitorInterval time.Duration `env:"NOOK_BUILD_JANITOR_INTERVAL" envDefault:"5m"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckDuration("NOOK_BUILD_TIMEOUT", c.Timeout, 10*time.Second, 2*time.Hour),
		config.CheckRange("NOOK_BUILD_MEMORY_MB", c.MemoryMB, 128, 65536),
		config.CheckRange("NOOK_BUILD_CPU_MILLICORES", c.CPUMillicores, 100, 64000),
		config.CheckRange("NOOK_BUILD_MAX_LOG_BYTES", c.MaxLogBytes, 64<<10, 64<<20),
		config.CheckDuration("NOOK_BUILD_QUEUE_TIMEOUT", c.QueueTimeout, 5*time.Second, 24*time.Hour),
		config.CheckRange("NOOK_BUILD_MAX_ATTEMPTS", c.MaxAttempts, 1, 10),
		config.CheckDuration("NOOK_BUILD_CLAIM_TIMEOUT", c.ClaimTimeout, time.Second, time.Hour),
		config.CheckDuration("NOOK_BUILD_ACCEPT_TIMEOUT", c.AcceptTimeout, time.Second, 10*time.Minute),
		config.CheckDuration("NOOK_BUILD_TICK_INTERVAL", c.TickInterval, 50*time.Millisecond, time.Minute),
		config.CheckRange("NOOK_IMAGE_RETENTION_COUNT", c.ImageRetention, 1, 1000),
		config.CheckDuration("NOOK_BUILD_ARTIFACT_RETENTION", c.ArtifactRetention, time.Hour, 10*365*24*time.Hour),
		config.CheckDuration("NOOK_BUILD_JANITOR_INTERVAL", c.JanitorInterval, 100*time.Millisecond, 24*time.Hour),
	)
}

// Fixed timings.
const (
	// ownerTTL is the lifetime of a deployment's owner lock; the owner
	// renews it every tick, so it only lapses when the owner dies.
	ownerTTL = 30 * time.Second
	// dispatchTimeout bounds handing a build command to an agent.
	dispatchTimeout = 15 * time.Second
	// resultGrace is extra time after the build timeout before a build
	// whose agent never reported is considered lost.
	resultGrace = 2 * time.Minute
	// cancelGrace: a build asked to stop that has not confirmed within
	// this time is recorded as canceled anyway.
	cancelGrace = time.Minute
	// tokenMargin extends registry tokens beyond the build timeout.
	tokenMargin = 10 * time.Minute
	// maxOwned bounds deployments one instance watches at once.
	maxOwned = 256
)
