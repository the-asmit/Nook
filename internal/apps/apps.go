package apps

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// Queue is the build queue as the apps service sees it.
type Queue interface {
	// Enqueue adds a job for a queued deployment.
	Enqueue(ctx context.Context, deploymentID uuid.UUID) error
	// Wake tells whoever handles a deployment to look at it again (after a
	// cancellation request, for example).
	Wake(ctx context.Context, deploymentID uuid.UUID)
}

// Service implements app and deployment operations.
type Service struct {
	store   *store.Store
	objects *objstore.Client
	queue   Queue
	keyring *secrets.Keyring
	cfg     Config
	now     func() time.Time
}

// NewService returns the service. The keyring encrypts environment values.
func NewService(st *store.Store, objects *objstore.Client, queue Queue, keyring *secrets.Keyring, cfg Config) *Service {
	return &Service{store: st, objects: objects, queue: queue, keyring: keyring, cfg: cfg, now: time.Now}
}

// RepositoryName is the registry repository of an app's images. IDs, not
// slugs, so a deleted app's slug can be reused without inheriting images.
func RepositoryName(workspaceID, appID uuid.UUID) string {
	return workspaceID.String() + "/" + appID.String()
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// ValidSlug reports whether s can name an app: a DNS label of at most 40
// lower-case letters, digits and inner hyphens (it becomes a host name).
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

// Spec is what a caller sets when creating an app; zero values take the
// defaults.
type Spec struct {
	Slug            string
	Name            string
	Port            int32
	HealthCheckPath string
	MemoryMB        int32
	CPUMillicores   int32
	// StartupTimeoutSeconds bounds how long a new instance may take to
	// pass its health check.
	StartupTimeoutSeconds int32
	// ReadOnlyRootfs runs the container with a read-only root file system.
	ReadOnlyRootfs bool
}

func (s *Service) normalize(spec Spec) (Spec, error) {
	if !ValidSlug(spec.Slug) {
		return spec, apperr.Invalid("invalid_slug", "app slug must be 1 to 40 lower-case letters, digits or inner hyphens")
	}
	spec.Name = strings.TrimSpace(spec.Name)
	if spec.Name == "" {
		spec.Name = spec.Slug
	}
	if utf8.RuneCountInString(spec.Name) > 100 {
		return spec, apperr.Invalid("invalid_name", "app name must be at most 100 characters")
	}
	if spec.Port == 0 {
		spec.Port = DefaultPort
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return spec, apperr.Invalid("invalid_port", "port must be between 1 and 65535")
	}
	if spec.HealthCheckPath == "" {
		spec.HealthCheckPath = DefaultHealthCheckPath
	}
	if !validPath(spec.HealthCheckPath) {
		return spec, apperr.Invalid("invalid_health_check_path", "health check path must start with / and be at most 200 printable characters")
	}
	if spec.MemoryMB == 0 {
		spec.MemoryMB = DefaultMemoryMB
	}
	if spec.MemoryMB < minMemoryMB || spec.MemoryMB > s.cfg.MaxAppMemoryMB {
		return spec, apperr.Invalid("invalid_memory", "memory must be between %d and %d MB", minMemoryMB, s.cfg.MaxAppMemoryMB)
	}
	if spec.CPUMillicores == 0 {
		spec.CPUMillicores = DefaultCPUMillicores
	}
	if spec.CPUMillicores < minCPUMillicores || spec.CPUMillicores > s.cfg.MaxAppCPUMillicores {
		return spec, apperr.Invalid("invalid_cpu", "cpu must be between %d and %d millicores", minCPUMillicores, s.cfg.MaxAppCPUMillicores)
	}
	if spec.StartupTimeoutSeconds == 0 {
		spec.StartupTimeoutSeconds = int32(DefaultStartupTimeout / time.Second)
	}
	maxStartup := int32(s.cfg.MaxStartupTimeout / time.Second) //nolint:gosec // G115: validated to be at most an hour.
	if spec.StartupTimeoutSeconds < 1 || spec.StartupTimeoutSeconds > maxStartup {
		return spec, apperr.Invalid("invalid_startup_timeout", "startup timeout must be between 1 and %d seconds", maxStartup)
	}
	return spec, nil
}

func validPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 200 {
		return false
	}
	for i := range len(p) {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// errAppNotFound is the single answer for missing apps.
func errAppNotFound() error { return apperr.NotFound("app not found") }

// resolve finds a live app in a workspace the actor belongs to.
func resolve(ctx context.Context, q *store.Queries, actor workspace.Actor, wsSlug, appSlug string) (workspace.View, store.App, error) {
	v, err := workspace.Resolve(ctx, q, actor, wsSlug)
	if err != nil {
		return v, store.App{}, err
	}
	if !ValidSlug(appSlug) {
		return v, store.App{}, errAppNotFound()
	}
	app, err := q.GetApp(ctx, store.GetAppParams{WorkspaceID: v.Workspace.ID, Slug: appSlug})
	if store.IsNotFound(err) {
		return v, store.App{}, errAppNotFound()
	}
	if err != nil {
		return v, store.App{}, fmt.Errorf("look up app: %w", err)
	}
	return v, app, nil
}

// Quota is a workspace's effective quota.
type Quota struct {
	MaxApps             int32 `json:"max_apps"`
	MaxConcurrentBuilds int32 `json:"max_concurrent_builds"`
	// MaxMemoryMB caps the memory the workspace's instances reserve.
	MaxMemoryMB int32 `json:"max_memory_mb"`
	// Default is true when no override is set.
	Default bool `json:"default"`
}

// QuotaFor returns a workspace's effective quota.
func (s *Service) QuotaFor(ctx context.Context, q *store.Queries, workspaceID uuid.UUID) (Quota, error) {
	row, err := q.GetWorkspaceQuota(ctx, workspaceID)
	if store.IsNotFound(err) {
		return Quota{
			MaxApps: s.cfg.DefaultMaxApps, MaxConcurrentBuilds: s.cfg.DefaultMaxConcurrentBuilds,
			MaxMemoryMB: s.cfg.DefaultMaxMemoryMB, Default: true,
		}, nil
	}
	if err != nil {
		return Quota{}, fmt.Errorf("read quota: %w", err)
	}
	return Quota{MaxApps: row.MaxApps, MaxConcurrentBuilds: row.MaxConcurrentBuilds, MaxMemoryMB: row.MaxMemoryMb}, nil
}

// MemoryQuotaMB returns a workspace's memory quota (for the rollout
// controller's placement check).
func (s *Service) MemoryQuotaMB(ctx context.Context, q *store.Queries, workspaceID uuid.UUID) (int64, error) {
	quota, err := s.QuotaFor(ctx, q, workspaceID)
	return int64(quota.MaxMemoryMB), err
}

// Create makes an app in a workspace the actor belongs to.
func (s *Service) Create(ctx context.Context, actor workspace.Actor, wsSlug string, spec Spec) (store.App, error) {
	spec, invalid := s.normalize(spec)
	if invalid != nil {
		return store.App{}, invalid
	}
	var app store.App
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := workspace.Resolve(ctx, q, actor, wsSlug)
		if err != nil {
			return err
		}
		if _, err = q.LockWorkspace(ctx, v.Workspace.ID); err != nil {
			return fmt.Errorf("lock workspace: %w", err)
		}
		quota, err := s.QuotaFor(ctx, q, v.Workspace.ID)
		if err != nil {
			return err
		}
		n, err := q.CountLiveApps(ctx, v.Workspace.ID)
		if err != nil {
			return fmt.Errorf("count apps: %w", err)
		}
		if n >= int64(quota.MaxApps) {
			return apperr.Conflict("quota_exceeded", "this workspace may have at most %d apps", quota.MaxApps)
		}
		app, err = q.CreateApp(ctx, store.CreateAppParams{
			WorkspaceID: v.Workspace.ID, Slug: spec.Slug, Name: spec.Name, CreatedBy: &actor.UserID,
			Port: spec.Port, HealthCheckPath: spec.HealthCheckPath, MemoryMb: spec.MemoryMB, CpuMillicores: spec.CPUMillicores,
			StartupTimeoutSeconds: spec.StartupTimeoutSeconds, ReadOnlyRootfs: spec.ReadOnlyRootfs,
		})
		if err != nil {
			return err
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionAppCreate, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"slug": app.Slug},
		})
	})
	if store.IsUniqueViolation(err, "apps_workspace_slug_active_key") {
		return store.App{}, apperr.Conflict("slug_taken", "an app named %q already exists in this workspace", spec.Slug)
	}
	return app, err
}

// List returns a page of the workspace's apps ordered by slug.
func (s *Service) List(ctx context.Context, actor workspace.Actor, wsSlug, afterSlug string, limit int32) ([]store.App, error) {
	v, err := workspace.Resolve(ctx, s.store.Queries, actor, wsSlug)
	if err != nil {
		return nil, err
	}
	apps, err := s.store.ListApps(ctx, store.ListAppsParams{WorkspaceID: v.Workspace.ID, AfterSlug: afterSlug, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	return apps, nil
}

// Get returns one app.
func (s *Service) Get(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (store.App, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	return app, err
}

// Delete removes an app (admins and owners only). Its waiting deployments
// are canceled, running builds and instances stopped; its images, sources
// and logs are purged in the background.
func (s *Service) Delete(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) error {
	var building, releasing []uuid.UUID
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		if !v.Allows(store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only workspace admins and owners can delete apps")
		}
		if _, err = q.SoftDeleteApp(ctx, app.ID); err != nil {
			return fmt.Errorf("delete app: %w", err)
		}
		deps, err := q.ListDeployments(ctx, store.ListDeploymentsParams{AppID: app.ID, BeforeNumber: app.NextDeploymentNumber, RowLimit: 1000})
		if err != nil {
			return fmt.Errorf("list deployments: %w", err)
		}
		for i := range deps {
			d := &deps[i]
			switch d.Status {
			case store.DeploymentStatusPending, store.DeploymentStatusUploading, store.DeploymentStatusQueued:
				if _, err := q.CancelWaitingDeployment(ctx, store.CancelWaitingDeploymentParams{ID: d.ID, Reason: "the app was deleted"}); err != nil && !store.IsNotFound(err) {
					return fmt.Errorf("cancel deployment: %w", err)
				}
			case store.DeploymentStatusBuilding:
				if _, err := q.RequestCancel(ctx, d.ID); err != nil && !store.IsNotFound(err) {
					return fmt.Errorf("cancel build: %w", err)
				}
				building = append(building, d.ID)
			case store.DeploymentStatusBuilt, store.DeploymentStatusDeploying, store.DeploymentStatusLive:
				// The rollout controller stops the app's instances.
				releasing = append(releasing, d.ID)
			default:
				// Finished deployments need nothing.
			}
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionAppDelete, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"slug": app.Slug},
		})
	})
	if err != nil {
		return err
	}
	for _, id := range building {
		s.queue.Wake(ctx, id)
	}
	for _, id := range releasing {
		s.release(ctx, id)
	}
	return nil
}

// GetQuota returns a workspace's quota (instance admins).
func (s *Service) GetQuota(ctx context.Context, wsSlug string) (Quota, error) {
	ws, err := s.workspaceBySlug(ctx, wsSlug)
	if err != nil {
		return Quota{}, err
	}
	return s.QuotaFor(ctx, s.store.Queries, ws.ID)
}

// SetQuota overrides a workspace's quota (instance admins). A nil
// maxMemory keeps the workspace's current memory quota.
func (s *Service) SetQuota(ctx context.Context, actor workspace.Actor, wsSlug string, maxApps, maxBuilds int32, maxMemory *int32) (Quota, error) {
	if maxApps < 0 || maxApps > 10000 || maxBuilds < 0 || maxBuilds > 100 {
		return Quota{}, apperr.Invalid("invalid_quota", "max_apps must be 0..10000 and max_concurrent_builds 0..100")
	}
	if maxMemory != nil && (*maxMemory < 0 || *maxMemory > maxQuotaMemoryMB) {
		return Quota{}, apperr.Invalid("invalid_quota", "max_memory_mb must be 0..%d", maxQuotaMemoryMB)
	}
	ws, err := s.workspaceBySlug(ctx, wsSlug)
	if err != nil {
		return Quota{}, err
	}
	var out Quota
	err = s.store.InTx(ctx, func(q *store.Queries) error {
		current, quotaErr := s.QuotaFor(ctx, q, ws.ID)
		if quotaErr != nil {
			return quotaErr
		}
		memory := current.MaxMemoryMB
		if maxMemory != nil {
			memory = *maxMemory
		}
		if _, upErr := q.UpsertWorkspaceQuota(ctx, store.UpsertWorkspaceQuotaParams{
			WorkspaceID: ws.ID, MaxApps: maxApps, MaxConcurrentBuilds: maxBuilds, MaxMemoryMb: memory, UpdatedBy: &actor.UserID,
		}); upErr != nil {
			return fmt.Errorf("set quota: %w", upErr)
		}
		out = Quota{MaxApps: maxApps, MaxConcurrentBuilds: maxBuilds, MaxMemoryMB: memory}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &ws.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionQuotaUpdate, TargetType: audit.TargetWorkspace, TargetID: ws.ID.String(),
			Metadata: map[string]any{"max_apps": maxApps, "max_concurrent_builds": maxBuilds, "max_memory_mb": memory},
		})
	})
	if err != nil {
		return Quota{}, err
	}
	return out, nil
}

func (s *Service) workspaceBySlug(ctx context.Context, slug string) (store.Workspace, error) {
	if !workspace.ValidSlug(slug) {
		return store.Workspace{}, apperr.NotFound("workspace not found")
	}
	ws, err := s.store.GetWorkspaceBySlug(ctx, slug)
	if store.IsNotFound(err) {
		return store.Workspace{}, apperr.NotFound("workspace not found")
	}
	if err != nil {
		return store.Workspace{}, fmt.Errorf("look up workspace: %w", err)
	}
	return ws, nil
}
