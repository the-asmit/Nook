// Package appdb runs app databases: one PostgreSQL server per installation
// (the nook-postgres image on a node an agent manages), a database and a
// role per app, continuous WAL archiving and base backups with WAL-G to
// S3-compatible storage (encrypted), and failover by restoring the server
// from those backups on another node. The leader drives everything; the
// API layer only records intent.
package appdb

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/platform/config"
)

// Config configures app databases. Storage settings default to Nook's own
// (NOOK_S3_*); the server's container reaches the endpoint, so it may
// need another address than the control plane uses.
type Config struct {
	// Image is the nook-postgres image (pinned by digest outside
	// development). Empty disables app databases.
	Image string `env:"NOOK_APPDB_IMAGE"`
	// Backups go to s3://BackupBucket/BackupPrefix.
	BackupBucket string `env:"NOOK_APPDB_BACKUP_BUCKET"`
	BackupPrefix string `env:"NOOK_APPDB_BACKUP_PREFIX" envDefault:"appdb"`
	// S3Endpoint is the storage service as the server's container reaches
	// it; region and credentials default to Nook's. Prefer credentials
	// limited to the backup bucket: the server's node holds them.
	S3Endpoint        string        `env:"NOOK_APPDB_S3_ENDPOINT"`
	S3Region          string        `env:"NOOK_APPDB_S3_REGION"`
	S3AccessKeyID     string        `env:"NOOK_APPDB_S3_ACCESS_KEY_ID"`
	S3SecretAccessKey config.Secret `env:"NOOK_APPDB_S3_SECRET_ACCESS_KEY"`
	// ArchiveTimeout is PostgreSQL's archive_timeout: the most recent
	// writes not yet archived when the server's node dies are lost, so it
	// is the recovery point objective of a failover.
	ArchiveTimeout time.Duration `env:"NOOK_APPDB_ARCHIVE_TIMEOUT" envDefault:"60s"`
	// BackupInterval is how often a base backup is taken.
	BackupInterval time.Duration `env:"NOOK_APPDB_BACKUP_INTERVAL" envDefault:"24h"`
	// Retention keeps backups (and the WAL they need) this long.
	Retention time.Duration `env:"NOOK_APPDB_RETENTION" envDefault:"168h"`
	// The server's reservation on its node.
	MemoryMB      int32 `env:"NOOK_APPDB_MEMORY_MB" envDefault:"512"`
	CPUMillicores int32 `env:"NOOK_APPDB_CPU_MILLICORES" envDefault:"1000"`
	// MaxConnections is the server's max_connections; ConnectionLimit is
	// each app role's.
	MaxConnections  int32 `env:"NOOK_APPDB_MAX_CONNECTIONS" envDefault:"200"`
	ConnectionLimit int32 `env:"NOOK_APPDB_CONNECTION_LIMIT" envDefault:"20"`
	// MinFreeDiskPercent: new databases are refused while the server's
	// node has less free disk than this, and a server is only placed on a
	// node with more.
	MinFreeDiskPercent int `env:"NOOK_APPDB_MIN_FREE_DISK_PERCENT" envDefault:"10"`
	// NodeLabel: nodes labeled NodeLabel=true are preferred for the server.
	NodeLabel string `env:"NOOK_APPDB_NODE_LABEL" envDefault:"nook.database"`
	// AdminHost overrides the host the control plane connects to (the
	// server's port stays), for development where the control plane
	// reaches published ports on 127.0.0.1.
	AdminHost string `env:"NOOK_APPDB_ADMIN_HOST"`
	// Interval paces the leader's pass; MonitorInterval its measurements.
	Interval        time.Duration `env:"NOOK_APPDB_INTERVAL" envDefault:"5s"`
	MonitorInterval time.Duration `env:"NOOK_APPDB_MONITOR_INTERVAL" envDefault:"30s"`
	// Dumps: at most DumpMaxBytes (one storage object), kept DumpTTL.
	DumpMaxBytes int64         `env:"NOOK_APPDB_DUMP_MAX_BYTES" envDefault:"5368709120"`
	DumpTTL      time.Duration `env:"NOOK_APPDB_DUMP_TTL" envDefault:"1h"`
}

var (
	prefixPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?(/[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?){0,4}$`)
	labelPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?$`)
	imagePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}(@sha256:[0-9a-f]{64})?$`)
)

// Enabled reports whether app databases are configured.
func (c *Config) Enabled() bool { return c.Image != "" }

// Resolve fills storage settings left empty from Nook's own.
func (c *Config) Resolve(s3 *objstore.Config) {
	if c.BackupBucket == "" {
		c.BackupBucket = s3.Bucket
	}
	if c.S3Endpoint == "" {
		c.S3Endpoint = s3.Endpoint
	}
	if c.S3Region == "" {
		c.S3Region = s3.Region
	}
	if c.S3AccessKeyID == "" && c.S3SecretAccessKey.IsZero() {
		c.S3AccessKeyID, c.S3SecretAccessKey = s3.AccessKeyID, s3.SecretAccessKey
	}
}

// Validate checks the configuration (after Resolve).
func (c *Config) Validate(requireTLS bool) error {
	if !c.Enabled() {
		return nil
	}
	var errs []error
	if !imagePattern.MatchString(c.Image) {
		errs = append(errs, errors.New("NOOK_APPDB_IMAGE: invalid image reference"))
	} else if requireTLS && !strings.Contains(c.Image, "@sha256:") {
		errs = append(errs, errors.New("NOOK_APPDB_IMAGE: must be pinned by digest (name:tag@sha256:...) outside development"))
	}
	if !prefixPattern.MatchString(c.BackupPrefix) {
		errs = append(errs, errors.New("NOOK_APPDB_BACKUP_PREFIX: lower-case path segments separated by '/'"))
	}
	if !prefixPattern.MatchString(c.BackupBucket) || strings.Contains(c.BackupBucket, "/") {
		errs = append(errs, errors.New("NOOK_APPDB_BACKUP_BUCKET: invalid bucket name"))
	}
	u, err := url.Parse(c.S3Endpoint)
	switch {
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || strings.Trim(u.Path, "/") != "":
		errs = append(errs, fmt.Errorf("NOOK_APPDB_S3_ENDPOINT: must be an http(s) URL without path, got %q", c.S3Endpoint))
	case requireTLS && u.Scheme != "https":
		errs = append(errs, errors.New("NOOK_APPDB_S3_ENDPOINT: must use https outside development"))
	}
	if c.S3Region == "" || len(c.S3Region) > 64 || c.S3AccessKeyID == "" || c.S3SecretAccessKey.IsZero() {
		errs = append(errs, errors.New("NOOK_APPDB_S3_*: region and credentials are required"))
	}
	if !labelPattern.MatchString(c.NodeLabel) {
		errs = append(errs, errors.New("NOOK_APPDB_NODE_LABEL: invalid label key"))
	}
	if c.AdminHost != "" && !validHost(c.AdminHost) {
		errs = append(errs, errors.New("NOOK_APPDB_ADMIN_HOST: must be an IP address"))
	}
	errs = append(errs,
		config.CheckDuration("NOOK_APPDB_ARCHIVE_TIMEOUT", c.ArchiveTimeout, 10*time.Second, time.Hour),
		config.CheckDuration("NOOK_APPDB_BACKUP_INTERVAL", c.BackupInterval, time.Minute, 30*24*time.Hour),
		config.CheckDuration("NOOK_APPDB_RETENTION", c.Retention, time.Hour, 365*24*time.Hour),
		config.CheckRange("NOOK_APPDB_MEMORY_MB", c.MemoryMB, 128, 1048576),
		config.CheckRange("NOOK_APPDB_CPU_MILLICORES", c.CPUMillicores, 100, 1024000),
		config.CheckRange("NOOK_APPDB_MAX_CONNECTIONS", c.MaxConnections, 20, 10000),
		config.CheckRange("NOOK_APPDB_CONNECTION_LIMIT", c.ConnectionLimit, 1, c.MaxConnections),
		config.CheckRange("NOOK_APPDB_MIN_FREE_DISK_PERCENT", c.MinFreeDiskPercent, 0, 90),
		config.CheckDuration("NOOK_APPDB_INTERVAL", c.Interval, 100*time.Millisecond, time.Minute),
		config.CheckDuration("NOOK_APPDB_MONITOR_INTERVAL", c.MonitorInterval, time.Second, time.Hour),
		config.CheckRange("NOOK_APPDB_DUMP_MAX_BYTES", c.DumpMaxBytes, 1<<20, 5<<30),
		config.CheckDuration("NOOK_APPDB_DUMP_TTL", c.DumpTTL, time.Minute, 24*time.Hour),
	)
	return errors.Join(errs...)
}

// walgPrefix is WAL-G's storage prefix.
func (c *Config) walgPrefix() string { return "s3://" + c.BackupBucket + "/" + c.BackupPrefix }
