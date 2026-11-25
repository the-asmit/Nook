// Package apps manages apps and their deployments: who may create and
// delete them, per-workspace quotas, and the upload of source archives
// that turns into a queued build.
//
// Every operation resolves the workspace through the caller's own
// membership first (non-members see "not found"), then the app inside
// that workspace. Members may create apps, deploy and read logs; only
// admins and owners may delete apps.
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
	// Upper bounds for an app's resource limits.
	MaxAppMemoryMB      int32 `env:"NOOK_APP_MAX_MEMORY_MB" envDefault:"4096"`
	MaxAppCPUMillicores int32 `env:"NOOK_APP_MAX_CPU_MILLICORES" envDefault:"4000"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckRange("NOOK_SOURCE_MAX_BYTES", c.MaxSourceBytes, 1<<20, 5<<30),
		config.CheckDuration("NOOK_UPLOAD_URL_TTL", c.UploadURLTTL, time.Minute, 12*time.Hour),
		config.CheckRange("NOOK_QUOTA_MAX_APPS", c.DefaultMaxApps, 0, 10000),
		config.CheckRange("NOOK_QUOTA_MAX_CONCURRENT_BUILDS", c.DefaultMaxConcurrentBuilds, 0, 100),
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
	// minimums keep limits meaningful.
	minMemoryMB      = 16
	minCPUMillicores = 10
)
