// Package apps manages apps and their deployments: who may create and
// delete them, per-workspace quotas, the upload of source archives that
// turns into a queued build, environment variables (encrypted), and the
// lifecycle requests that the rollout controller carries out (stop,
// start, rollback, configuration releases).
//
// Every operation resolves the workspace through the caller's own
// membership first (non-members see "not found"), then the app inside
// that workspace. Members may create, configure, deploy, stop, start and
// roll back apps, read logs and set plain environment variables; only
// admins and owners may delete apps and set, change or remove secrets.
package apps

import (
	"errors"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds the limits and defaults for apps and deployments.
type Config struct {
	// MaxSourceBytes limits an uploaded source archive.
	MaxSourceBytes int64 `env:"NOOK_SOURCE_MAX_BYTES" envDefault:"209715200"`
	// UploadURLTTL is how long a presigned upload URL stays valid.
	UploadURLTTL time.Duration `env:"NOOK_UPLOAD_URL_TTL" envDefault:"15m"`
	// Default quotas for workspaces without an override.
	DefaultMaxApps             int32 `env:"NOOK_QUOTA_MAX_APPS" envDefault:"20"`
	DefaultMaxConcurrentBuilds int32 `env:"NOOK_QUOTA_MAX_CONCURRENT_BUILDS" envDefault:"2"`
	// DefaultMaxMemoryMB caps the memory a workspace's running apps reserve.
	DefaultMaxMemoryMB int32 `env:"NOOK_QUOTA_MAX_MEMORY_MB" envDefault:"8192"`
	// MaxStartupTimeout is the longest startup timeout an app may ask for
	// in nook.toml.
	MaxStartupTimeout time.Duration `env:"NOOK_APP_MAX_STARTUP_TIMEOUT" envDefault:"10m"`
	// Upper bounds for an app's resource limits.
	MaxAppMemoryMB      int32 `env:"NOOK_APP_MAX_MEMORY_MB" envDefault:"4096"`
	MaxAppCPUMillicores int32 `env:"NOOK_APP_MAX_CPU_MILLICORES" envDefault:"4000"`
	// AllowPublicApps lets admins open apps to anyone without sign-in.
	AllowPublicApps bool `env:"NOOK_ALLOW_PUBLIC_APPS" envDefault:"false"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckRange("NOOK_SOURCE_MAX_BYTES", c.MaxSourceBytes, 1<<20, 5<<30),
		config.CheckDuration("NOOK_UPLOAD_URL_TTL", c.UploadURLTTL, time.Minute, 12*time.Hour),
		config.CheckRange("NOOK_QUOTA_MAX_APPS", c.DefaultMaxApps, 0, 10000),
		config.CheckRange("NOOK_QUOTA_MAX_CONCURRENT_BUILDS", c.DefaultMaxConcurrentBuilds, 0, 100),
		config.CheckRange("NOOK_QUOTA_MAX_MEMORY_MB", c.DefaultMaxMemoryMB, 0, maxQuotaMemoryMB),
		config.CheckDuration("NOOK_APP_MAX_STARTUP_TIMEOUT", c.MaxStartupTimeout, DefaultStartupTimeout, time.Hour),
		config.CheckRange("NOOK_APP_MAX_MEMORY_MB", c.MaxAppMemoryMB, DefaultMemoryMB, 1048576),
		config.CheckRange("NOOK_APP_MAX_CPU_MILLICORES", c.MaxAppCPUMillicores, DefaultCPUMillicores, 1024000),
	)
}

// Defaults for new apps.
const (
	DefaultPort            = 8080
	DefaultHealthCheckPath = "/"
	DefaultMemoryMB        = 256
	DefaultCPUMillicores   = 500
	DefaultStartupTimeout  = 60 * time.Second
	// maxQuotaMemoryMB bounds a workspace memory quota (10 TiB).
	maxQuotaMemoryMB = 10485760
	// minimums keep limits meaningful.
	minMemoryMB      = 16
	minCPUMillicores = 10
)
