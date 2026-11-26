package apps

import (
	"context"
	"fmt"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// release hands a deployment to the deployment queue so its owner releases
// it or brings its instances to the app's desired state. A lost job is
// re-added by the janitor.
func (s *Service) release(ctx context.Context, deploymentID uuid.UUID) {
	if err := s.queue.Enqueue(ctx, deploymentID); err == nil {
		_ = s.store.MarkEnqueued(ctx, deploymentID)
	}
	s.queue.Wake(ctx, deploymentID)
}

// Settings changes an app's runtime settings; nil fields stay as they are.
type Settings struct {
	Port                  *int32
	HealthCheckPath       *string
	MemoryMB              *int32
	CPUMillicores         *int32
	StartupTimeoutSeconds *int32
	ReadOnlyRootfs        *bool
	// SleepAfter is a duration ("15m") or "never".
	SleepAfter *string
}

// Update changes an app's settings (any member). They apply to the next
// instance started (the next deployment, or a restart).
func (s *Service) Update(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, set Settings) (store.App, error) {
	var out store.App
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		spec := Spec{
			Slug: app.Slug, Name: app.Name, Port: deref(set.Port, app.Port), HealthCheckPath: deref(set.HealthCheckPath, app.HealthCheckPath),
			MemoryMB: deref(set.MemoryMB, app.MemoryMb), CPUMillicores: deref(set.CPUMillicores, app.CpuMillicores),
			StartupTimeoutSeconds: deref(set.StartupTimeoutSeconds, app.StartupTimeoutSeconds), ReadOnlyRootfs: deref(set.ReadOnlyRootfs, app.ReadOnlyRootfs),
			SleepAfter: deref(set.SleepAfter, FormatSleepAfter(app.SleepAfterSeconds)),
		}
		if spec, err = s.normalize(&spec); err != nil {
			return err
		}
		out, err = q.UpdateAppSettings(ctx, store.UpdateAppSettingsParams{
			ID: app.ID, Port: spec.Port, HealthCheckPath: spec.HealthCheckPath, MemoryMb: spec.MemoryMB, CpuMillicores: spec.CPUMillicores,
			StartupTimeoutSeconds: spec.StartupTimeoutSeconds, ReadOnlyRootfs: spec.ReadOnlyRootfs, SleepAfterSeconds: spec.sleepAfterSeconds,
		})
		if err != nil {
			return fmt.Errorf("update app: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionAppUpdate, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{
				"slug": app.Slug, "port": spec.Port, "health_check_path": spec.HealthCheckPath, "memory_mb": spec.MemoryMB,
				"cpu_millicores": spec.CPUMillicores, "startup_timeout_seconds": spec.StartupTimeoutSeconds, "read_only_rootfs": spec.ReadOnlyRootfs,
				"sleep_after": FormatSleepAfter(spec.sleepAfterSeconds),
			},
		})
	})
	return out, err
}

func deref[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// Stop asks for the app to stop running; its instance is stopped and no
// new deployment is released until it is started again.
func (s *Service) Stop(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (store.App, error) {
	return s.setDesired(ctx, actor, wsSlug, appSlug, store.AppDesiredStateStopped)
}

// Start asks for the app to run: the newest deployment waiting to be
// released if there is one, otherwise the current deployment, started on
// a fresh instance if it crashed.
func (s *Service) Start(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (store.App, error) {
	return s.setDesired(ctx, actor, wsSlug, appSlug, store.AppDesiredStateRunning)
}

func (s *Service) setDesired(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, state store.AppDesiredState) (store.App, error) {
	var out store.App
	var wake []uuid.UUID
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		if out, err = q.SetDesiredState(ctx, store.SetDesiredStateParams{ID: app.ID, DesiredState: state}); err != nil {
			return fmt.Errorf("set desired state: %w", err)
		}
		// Starting or stopping an app ends any sleep: a started app runs.
		if err = q.ClearSleep(ctx, app.ID); err != nil {
			return fmt.Errorf("clear sleep: %w", err)
		}
		if app.CurrentDeploymentID != nil {
			wake = append(wake, *app.CurrentDeploymentID)
		}
		if state == store.AppDesiredStateRunning {
			if built, err := q.LatestBuiltDeployment(ctx, app.ID); err == nil {
				wake = append(wake, built.ID)
			} else if !store.IsNotFound(err) {
				return fmt.Errorf("find deployment to release: %w", err)
			}
		}
		action := audit.ActionAppStart
		if state == store.AppDesiredStateStopped {
			action = audit.ActionAppStop
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: action, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"slug": app.Slug},
		})
	})
	if err != nil {
		return store.App{}, err
	}
	for _, id := range wake {
		s.release(ctx, id)
	}
	s.events.Changed(ctx, out.ID)
	return out, nil
}

// Rollback releases an earlier deployment's image again with that
// deployment's environment snapshot, as a new deployment. With to == 0
// the target is the newest earlier deployment that was live once.
func (s *Service) Rollback(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, to int32) (store.Deployment, error) {
	var out store.Deployment
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		if _, err = q.LockApp(ctx, app.ID); err != nil {
			return fmt.Errorf("lock app: %w", err)
		}
		target, err := s.rollbackTarget(ctx, q, &app, to)
		if err != nil {
			return err
		}
		number, err := q.NextDeploymentNumber(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("next deployment number: %w", err)
		}
		targetNumber := target.Number
		out, err = q.CreateReleaseDeployment(ctx, store.CreateReleaseDeploymentParams{
			AppID: app.ID, Number: number, Kind: store.DeploymentKindRollback, ImageOfDeploymentID: &target.ID,
			RollbackTo: &targetNumber, EnvSnapshotID: target.EnvSnapshotID,
			SourceKey: target.SourceKey, SourceSha256: target.SourceSha256, SourceSize: target.SourceSize,
			ImageDigest: target.ImageDigest, CreatedBy: &actor.UserID,
		})
		if err != nil {
			return fmt.Errorf("create rollback deployment: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionDeploymentRollback, TargetType: audit.TargetDeployment, TargetID: out.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "number": number, "rollback_to": targetNumber},
		})
	})
	if err != nil {
		return store.Deployment{}, err
	}
	s.release(ctx, out.ID)
	return out, nil
}

func (s *Service) rollbackTarget(ctx context.Context, q *store.Queries, app *store.App, to int32) (store.Deployment, error) {
	if to == 0 {
		before := app.NextDeploymentNumber
		if app.CurrentDeploymentID != nil {
			cur, err := q.GetDeploymentByID(ctx, *app.CurrentDeploymentID)
			if err != nil {
				return store.Deployment{}, fmt.Errorf("read current deployment: %w", err)
			}
			before = cur.Number
		}
		d, err := q.DefaultRollbackTarget(ctx, store.DefaultRollbackTargetParams{AppID: app.ID, BeforeNumber: before})
		if store.IsNotFound(err) {
			return store.Deployment{}, apperr.Conflict("no_rollback_target", "there is no earlier released deployment to roll back to")
		}
		if err != nil {
			return store.Deployment{}, fmt.Errorf("find rollback target: %w", err)
		}
		return d, nil
	}
	d, err := s.deployment(ctx, q, app.ID, to)
	if err != nil {
		return store.Deployment{}, err
	}
	switch {
	case d.ImageDigest == nil:
		return store.Deployment{}, apperr.Conflict("not_built", "deployment #%d has no image (%s)", to, d.Status)
	case d.ImageDeletedAt != nil:
		return store.Deployment{}, apperr.Conflict("image_deleted", "the image of deployment #%d was deleted by the retention policy", to)
	case app.CurrentDeploymentID != nil && *app.CurrentDeploymentID == d.ID:
		return store.Deployment{}, apperr.Conflict("already_live", "deployment #%d is already live", to)
	}
	return d, nil
}

// Runtime is an app with what runs it.
type Runtime struct {
	App store.App
	// Live is the current deployment, if any.
	Live *store.Deployment
	// Instance is the newest instance of the current deployment (or of the
	// app when nothing is live).
	Instance *store.AppInstance
}

// GetRuntime returns an app with its live deployment and instance.
func (s *Service) GetRuntime(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Runtime, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return Runtime{}, err
	}
	rt := Runtime{App: app}
	var inst store.AppInstance
	if app.CurrentDeploymentID != nil {
		live, liveErr := s.store.GetDeploymentByID(ctx, *app.CurrentDeploymentID)
		if liveErr != nil {
			return Runtime{}, fmt.Errorf("read live deployment: %w", liveErr)
		}
		rt.Live = &live
		inst, err = s.store.LatestInstanceOfDeployment(ctx, live.ID)
		if err == nil {
			rt.Instance = &inst
		} else if !store.IsNotFound(err) {
			return Runtime{}, fmt.Errorf("read instance: %w", err)
		}
		return rt, nil
	}
	inst, err = s.store.LatestInstanceOfApp(ctx, app.ID)
	if err == nil {
		rt.Instance = &inst
	} else if !store.IsNotFound(err) {
		return Runtime{}, fmt.Errorf("read instance: %w", err)
	}
	return rt, nil
}

// LogInstance returns the app's instance to read logs from: the newest one
// whose container may still exist.
func (s *Service) LogInstance(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (store.AppInstance, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return store.AppInstance{}, err
	}
	inst, err := s.store.LatestInstanceWithContainer(ctx, app.ID)
	if store.IsNotFound(err) {
		return store.AppInstance{}, apperr.NotFound("the app has no running instance; deploy it first")
	}
	if err != nil {
		return store.AppInstance{}, fmt.Errorf("find instance: %w", err)
	}
	return inst, nil
}
