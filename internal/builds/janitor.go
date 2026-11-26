package builds

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/store"
)

// Janitor enforces retention and repairs what crashes leave behind. It
// runs on the elected leader only; every task is idempotent, so a brief
// overlap during a leadership change is harmless.
type Janitor struct {
	store    *store.Store
	queue    *Queue
	objects  *objstore.Client
	registry *registry.Client
	cfg      Config
	isLeader func() bool
	logger   *slog.Logger
	// extra are more leader-only cleanup tasks run on every tick.
	extra []func(context.Context) error
}

// Also adds a cleanup task run on every tick (by the leader).
func (j *Janitor) Also(task func(context.Context) error) { j.extra = append(j.extra, task) }

// NewJanitor returns the janitor.
func NewJanitor(d *Deps, queue *Queue, cfg *Config, isLeader func() bool) *Janitor {
	return &Janitor{store: d.Store, queue: queue, objects: d.Objects, registry: d.Registry, cfg: *cfg, isLeader: isLeader, logger: d.Logger}
}

// batch bounds the work of one task per run.
const batch = 200

// Run ticks until ctx ends.
func (j *Janitor) Run(ctx context.Context) {
	t := time.NewTicker(j.cfg.JanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if j.isLeader() {
				if err := j.Tick(ctx); err != nil && ctx.Err() == nil {
					j.logger.WarnContext(ctx, "janitor run incomplete", "error", err.Error())
				}
			}
		}
	}
}

// Tick runs every task once.
func (j *Janitor) Tick(ctx context.Context) error {
	errs := []error{
		j.requeueOrphans(ctx),
		j.expireUploads(ctx),
		j.enforceImageRetention(ctx),
		j.purgeDeletedApps(ctx),
		j.removeStrayImages(ctx),
		j.expireArtifacts(ctx),
	}
	for _, task := range j.extra {
		errs = append(errs, task(ctx))
	}
	return errors.Join(errs...)
}

// requeueOrphans re-adds jobs for active deployments nobody owns (their
// queue entry was lost, for example with a Redis restart).
func (j *Janitor) requeueOrphans(ctx context.Context) error {
	before := time.Now().Add(-2 * j.cfg.ClaimTimeout)
	deps, err := j.store.ListUnownedActiveDeployments(ctx, store.ListUnownedActiveDeploymentsParams{Before: &before, RowLimit: batch})
	if err != nil {
		return fmt.Errorf("list active deployments: %w", err)
	}
	for i := range deps {
		d := &deps[i]
		owned, err := hasOwner(ctx, j.queue.redis, d.ID)
		if err != nil {
			return err
		}
		if owned {
			continue
		}
		if err := j.queue.Enqueue(ctx, d.ID); err != nil {
			return err
		}
		if err := j.store.MarkEnqueued(ctx, d.ID); err != nil {
			return fmt.Errorf("mark enqueued: %w", err)
		}
		j.logger.InfoContext(ctx, "re-enqueued deployment without an owner", "deployment", d.ID.String())
	}
	return j.requeueDiverged(ctx, before)
}

// requeueDiverged re-adds jobs for live deployments whose instances do not
// match their app's desired state (a start or stop whose job was lost, or
// an app that could not be started for lack of capacity).
func (j *Janitor) requeueDiverged(ctx context.Context, before time.Time) error {
	deps, err := j.store.ListDeploymentsToConverge(ctx, store.ListDeploymentsToConvergeParams{Before: &before, RowLimit: batch})
	if err != nil {
		return fmt.Errorf("list live deployments to converge: %w", err)
	}
	for i := range deps {
		d := &deps[i]
		owned, err := hasOwner(ctx, j.queue.redis, d.ID)
		if err != nil {
			return err
		}
		if owned {
			continue
		}
		if err := j.queue.Enqueue(ctx, d.ID); err != nil {
			return err
		}
		if err := j.store.MarkEnqueued(ctx, d.ID); err != nil {
			return fmt.Errorf("mark enqueued: %w", err)
		}
	}
	return nil
}

// expireUploads fails deployments whose source never arrived and deletes
// anything that was partly uploaded.
func (j *Janitor) expireUploads(ctx context.Context) error {
	deps, err := j.store.ListAbandonedUploads(ctx, store.ListAbandonedUploadsParams{Before: time.Now().Add(-5 * time.Minute), RowLimit: batch})
	if err != nil {
		return fmt.Errorf("list abandoned uploads: %w", err)
	}
	for i := range deps {
		d := &deps[i]
		if _, err := j.store.MarkFailed(ctx, store.MarkFailedParams{ID: d.ID, Reason: "the source archive was not uploaded in time"}); err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("fail deployment: %w", err)
		}
		if err := j.objects.Delete(ctx, d.SourceKey); err != nil {
			return err
		}
		if err := j.store.MarkSourceDeleted(ctx, d.ID); err != nil {
			return fmt.Errorf("mark source deleted: %w", err)
		}
	}
	return nil
}

// enforceImageRetention deletes built images beyond the newest
// ImageRetention per app.
func (j *Janitor) enforceImageRetention(ctx context.Context) error {
	rows, err := j.store.ListImagesBeyondRetention(ctx, store.ListImagesBeyondRetentionParams{Keep: j.cfg.ImageRetention, RowLimit: batch})
	if err != nil {
		return fmt.Errorf("list images beyond retention: %w", err)
	}
	for _, r := range rows {
		if r.ImageDigest == nil {
			continue
		}
		if err := j.deleteImage(ctx, r.ID, r.AppID, *r.ImageDigest); err != nil {
			return err
		}
	}
	return nil
}

// deleteImage marks a deployment's image deleted and removes the manifest,
// unless another live deployment of the app has the same digest (an
// identical rebuild).
func (j *Janitor) deleteImage(ctx context.Context, deploymentID, appID uuid.UUID, digest string) error {
	app, err := j.store.GetAppByID(ctx, appID)
	if err != nil {
		return fmt.Errorf("read app: %w", err)
	}
	if err = j.store.MarkImageDeleted(ctx, deploymentID); err != nil {
		return fmt.Errorf("mark image deleted: %w", err)
	}
	shared, err := j.store.IsRecordedImage(ctx, store.IsRecordedImageParams{AppID: appID, ImageDigest: &digest})
	if err != nil {
		return fmt.Errorf("check shared image: %w", err)
	}
	if shared {
		return nil
	}
	return j.registry.DeleteManifest(ctx, apps.RepositoryName(app.WorkspaceID, app.ID), digest)
}

// purgeDeletedApps removes the images, sources and logs of deleted apps,
// then the apps themselves (with their deployments and builds).
func (j *Janitor) purgeDeletedApps(ctx context.Context) error {
	deleted, err := j.store.ListDeletedApps(ctx, batch)
	if err != nil {
		return fmt.Errorf("list deleted apps: %w", err)
	}
	for i := range deleted {
		app := &deleted[i]
		busy, err := j.store.ListDeployments(ctx, store.ListDeploymentsParams{AppID: app.ID, BeforeNumber: app.NextDeploymentNumber, RowLimit: 1000})
		if err != nil {
			return fmt.Errorf("list deployments: %w", err)
		}
		if slicesAny(busy, func(d store.Deployment) bool { return d.Status == store.DeploymentStatusBuilding }) {
			continue // wait for running builds to stop
		}
		images, err := j.store.ListImagesOfApp(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("list images: %w", err)
		}
		repo := apps.RepositoryName(app.WorkspaceID, app.ID)
		for _, im := range images {
			if im.ImageDigest != nil {
				if delErr := j.registry.DeleteManifest(ctx, repo, *im.ImageDigest); delErr != nil {
					return delErr
				}
			}
		}
		if cacheErr := j.deleteCache(ctx, apps.CacheRepositoryName(app.WorkspaceID, app.ID)); cacheErr != nil {
			return cacheErr
		}
		sources, err := j.store.ListSourcesOfApp(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("list sources: %w", err)
		}
		for _, s := range sources {
			if delErr := j.objects.Delete(ctx, s.SourceKey); delErr != nil {
				return delErr
			}
		}
		logs, err := j.store.ListLogsOfApp(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("list logs: %w", err)
		}
		for _, l := range logs {
			if l.LogKey != nil {
				if err := j.objects.Delete(ctx, *l.LogKey); err != nil {
					return err
				}
			}
		}
		if err := j.store.PurgeApp(ctx, app.ID); err != nil {
			return fmt.Errorf("purge app: %w", err)
		}
		j.logger.InfoContext(ctx, "purged deleted app", "app", app.ID.String(), "images", len(images))
	}
	return nil
}

// removeStrayImages deletes registry tags that are not the recorded image
// of a live deployment: pushes from abandoned attempts (an agent that was
// killed and later finished anyway) and repositories of purged apps.
func (j *Janitor) removeStrayImages(ctx context.Context) error {
	repos, err := j.registry.Repositories(ctx)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if base, isCache := strings.CutSuffix(repo, "/"+apps.CacheRepoSuffix); isCache {
			if err := j.removeStrayCache(ctx, repo, base); err != nil {
				return err
			}
			continue
		}
		wsID, appID, ok := parseRepository(repo)
		if !ok {
			continue
		}
		tags, err := j.registry.Tags(ctx, repo)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			stray, err := j.isStray(ctx, wsID, appID, tag)
			if err != nil {
				return err
			}
			if !stray {
				continue
			}
			digest, err := j.registry.TagDigest(ctx, repo, tag)
			if errors.Is(err, registry.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			recorded, err := j.store.IsRecordedImage(ctx, store.IsRecordedImageParams{AppID: appID, ImageDigest: &digest})
			if err != nil {
				return fmt.Errorf("check recorded image: %w", err)
			}
			if recorded {
				continue
			}
			if err := j.registry.DeleteManifest(ctx, repo, digest); err != nil {
				return err
			}
			j.logger.InfoContext(ctx, "removed stray image", "repository", repo, "tag", tag)
		}
	}
	return nil
}

// deleteCache removes every manifest of a build-cache repository; registry
// GC then collects the layers no image uses.
func (j *Janitor) deleteCache(ctx context.Context, repo string) error {
	tags, err := j.registry.Tags(ctx, repo)
	if err != nil {
		return err
	}
	for _, tag := range tags {
		digest, err := j.registry.TagDigest(ctx, repo, tag)
		if errors.Is(err, registry.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err := j.registry.DeleteManifest(ctx, repo, digest); err != nil {
			return err
		}
	}
	return nil
}

// removeStrayCache deletes the build cache of an app that no longer exists
// (or is not in the workspace the repository names): purged apps, and
// anything else in a cache repository's place.
func (j *Janitor) removeStrayCache(ctx context.Context, repo, base string) error {
	wsID, appID, ok := parseRepository(base)
	if ok {
		app, err := j.store.GetAppByID(ctx, appID)
		if err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("read app: %w", err)
		}
		if err == nil && app.WorkspaceID == wsID && app.DeletedAt == nil {
			return nil // a live app's cache: overwritten by every build
		}
	}
	if err := j.deleteCache(ctx, repo); err != nil {
		return err
	}
	j.logger.InfoContext(ctx, "removed stray build cache", "repository", repo)
	return nil
}

// isStray decides whether a tag "b-<build-id>" should go: its build is
// finished and its image is not a live deployment's, or nothing in the
// database knows it.
func (j *Janitor) isStray(ctx context.Context, wsID, appID uuid.UUID, tag string) (bool, error) {
	app, err := j.store.GetAppByID(ctx, appID)
	if store.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read app: %w", err)
	}
	if app.WorkspaceID != wsID {
		return true, nil
	}
	buildID, ok := buildIDFromTag(tag)
	if !ok {
		return true, nil // not a tag Nook pushed
	}
	b, err := j.store.GetBuild(ctx, buildID)
	if store.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read build: %w", err)
	}
	if b.FinishedAt == nil {
		return false, nil
	}
	dep, err := j.store.GetDeploymentByID(ctx, b.DeploymentID)
	if err != nil {
		return false, fmt.Errorf("read deployment: %w", err)
	}
	live := dep.Status == store.DeploymentStatusBuilt && dep.ImageDeletedAt == nil && dep.ImageDigest != nil &&
		b.ImageDigest != nil && *b.ImageDigest == *dep.ImageDigest
	return !live, nil
}

// expireArtifacts deletes source archives and build logs older than the
// retention window.
func (j *Janitor) expireArtifacts(ctx context.Context) error {
	before := time.Now().Add(-j.cfg.ArtifactRetention)
	sources, err := j.store.ListExpiredSources(ctx, store.ListExpiredSourcesParams{Before: before, RowLimit: batch})
	if err != nil {
		return fmt.Errorf("list expired sources: %w", err)
	}
	for _, s := range sources {
		if delErr := j.objects.Delete(ctx, s.SourceKey); delErr != nil {
			return delErr
		}
		if err = j.store.MarkSourceDeleted(ctx, s.ID); err != nil {
			return fmt.Errorf("mark source deleted: %w", err)
		}
	}
	logs, err := j.store.ListExpiredLogs(ctx, store.ListExpiredLogsParams{Before: &before, RowLimit: batch})
	if err != nil {
		return fmt.Errorf("list expired logs: %w", err)
	}
	for _, l := range logs {
		if l.LogKey != nil {
			if err := j.objects.Delete(ctx, *l.LogKey); err != nil {
				return err
			}
		}
		if err := j.store.ClearBuildLogKey(ctx, l.ID); err != nil {
			return fmt.Errorf("clear log key: %w", err)
		}
	}
	return nil
}

// buildIDFromTag parses a build tag "b-<build-id>".
func buildIDFromTag(tag string) (uuid.UUID, bool) {
	raw, ok := strings.CutPrefix(tag, "b-")
	if !ok {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(raw)
	return id, err == nil
}

func parseRepository(repo string) (uuid.UUID, uuid.UUID, bool) {
	ws, app, ok := strings.Cut(repo, "/")
	if !ok {
		return uuid.UUID{}, uuid.UUID{}, false
	}
	wsID, err1 := uuid.Parse(ws)
	appID, err2 := uuid.Parse(app)
	return wsID, appID, err1 == nil && err2 == nil
}

func slicesAny[T any](s []T, f func(T) bool) bool {
	for _, v := range s {
		if f(v) {
			return true
		}
	}
	return false
}
