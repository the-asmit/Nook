package apps

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// Upload is a created deployment with the presigned URL to upload to.
type Upload struct {
	Deployment store.Deployment
	App        store.App
	Upload     objstore.Upload
}

// SourceKey is the object key of a deployment's source archive: scoped by
// workspace, app and deployment, with 128 random bits so keys cannot be
// guessed from IDs alone.
func sourceKey(workspaceID, appID uuid.UUID, number int32) (string, error) {
	r := make([]byte, 16)
	if _, err := rand.Read(r); err != nil {
		return "", fmt.Errorf("random key: %w", err)
	}
	return fmt.Sprintf("sources/%s/%s/%d-%s.tar.gz", workspaceID, appID, number, hex.EncodeToString(r)), nil
}

// CreateDeployment registers a deploy of size bytes with the given SHA-256
// and returns where to upload the source. The upload URL only accepts
// exactly that content.
func (s *Service) CreateDeployment(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, size int64, sum []byte) (Upload, error) {
	if size <= 0 || size > s.cfg.MaxSourceBytes {
		return Upload{}, apperr.Invalid("source_too_large", "the source archive must be between 1 byte and %d bytes", s.cfg.MaxSourceBytes)
	}
	if len(sum) != 32 {
		return Upload{}, apperr.Invalid("invalid_checksum", "source_sha256 must be 64 hex digits")
	}
	var out Upload
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		number, err := q.NextDeploymentNumber(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("next deployment number: %w", err)
		}
		key, err := sourceKey(v.Workspace.ID, app.ID, number)
		if err != nil {
			return err
		}
		d, err := q.CreateDeployment(ctx, store.CreateDeploymentParams{
			AppID: app.ID, Number: number, SourceKey: key, SourceSha256: sum, SourceSize: size,
			UploadExpiresAt: s.now().Add(s.cfg.UploadURLTTL), CreatedBy: &actor.UserID,
		})
		if err != nil {
			return fmt.Errorf("create deployment: %w", err)
		}
		up := s.objects.PresignPut(key, size, sum, s.cfg.UploadURLTTL)
		if d, err = q.MarkDeploymentUploading(ctx, d.ID); err != nil {
			return fmt.Errorf("mark uploading: %w", err)
		}
		out = Upload{Deployment: d, App: app, Upload: up}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionDeploymentCreate, TargetType: audit.TargetDeployment, TargetID: d.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "number": number, "source_size": size},
		})
	})
	return out, err
}

// ConfirmUpload checks that the source archive is in storage with exactly
// the announced size and SHA-256 (as verified by the storage service) and
// queues the build. A newer queued deploy of the same app wins: older
// queued ones are canceled as superseded.
func (s *Service) ConfirmUpload(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, number int32) (store.Deployment, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return store.Deployment{}, err
	}
	d, err := s.deployment(ctx, s.store.Queries, app.ID, number)
	if err != nil {
		return store.Deployment{}, err
	}
	if d.Status != store.DeploymentStatusPending && d.Status != store.DeploymentStatusUploading {
		return store.Deployment{}, apperr.Conflict("not_awaiting_upload", "deployment #%d is %s, not waiting for its upload", number, d.Status)
	}
	info, err := s.objects.Head(ctx, d.SourceKey)
	if errors.Is(err, objstore.ErrNotFound) {
		return store.Deployment{}, apperr.Conflict("upload_missing", "the source archive of deployment #%d has not been uploaded", number)
	}
	if err != nil {
		return store.Deployment{}, fmt.Errorf("check upload: %w", err)
	}
	if info.Size != d.SourceSize || !bytes.Equal(info.SHA256, d.SourceSha256) {
		return store.Deployment{}, apperr.Conflict("upload_mismatch", "the uploaded archive does not match the announced size and checksum")
	}

	var queued store.Deployment
	err = s.store.InTx(ctx, func(q *store.Queries) error {
		if _, err = q.LockDeployment(ctx, d.ID); err != nil {
			return fmt.Errorf("lock deployment: %w", err)
		}
		queued, err = q.QueueDeployment(ctx, d.ID)
		if store.IsNotFound(err) {
			return apperr.Conflict("not_awaiting_upload", "deployment #%d is no longer waiting for its upload", number)
		}
		if err != nil {
			return fmt.Errorf("queue deployment: %w", err)
		}
		var newer bool
		newer, err = q.NewerQueuedExists(ctx, store.NewerQueuedExistsParams{AppID: app.ID, Number: number})
		if err != nil {
			return fmt.Errorf("check newer deployments: %w", err)
		}
		if newer {
			queued, err = q.CancelWaitingDeployment(ctx, store.CancelWaitingDeploymentParams{
				ID: d.ID, Reason: "superseded by a newer deployment of the same app",
			})
			return err
		}
		_, err = q.SupersedeQueued(ctx, store.SupersedeQueuedParams{
			AppID: app.ID, Number: number, Reason: "superseded by deployment #" + strconv.Itoa(int(number)),
		})
		return err
	})
	if err != nil {
		return store.Deployment{}, err
	}
	if queued.Status == store.DeploymentStatusQueued {
		// The deployment is durably queued in Postgres; if this fails the
		// janitor re-enqueues it.
		_ = s.queue.Enqueue(ctx, queued.ID)
	}
	return queued, nil
}

func (s *Service) deployment(ctx context.Context, q *store.Queries, appID uuid.UUID, number int32) (store.Deployment, error) {
	d, err := q.GetDeployment(ctx, store.GetDeploymentParams{AppID: appID, Number: number})
	if store.IsNotFound(err) {
		return store.Deployment{}, apperr.NotFound("deployment not found")
	}
	if err != nil {
		return store.Deployment{}, fmt.Errorf("look up deployment: %w", err)
	}
	return d, nil
}

// Detail is a deployment with its app, build attempts and newest instance.
type Detail struct {
	Workspace  store.Workspace
	App        store.App
	Deployment store.Deployment
	Builds     []store.Build
	Instance   *store.AppInstance
}

// GetDeployment returns one deployment with its builds.
func (s *Service) GetDeployment(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, number int32) (Detail, error) {
	v, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return Detail{}, err
	}
	d, err := s.deployment(ctx, s.store.Queries, app.ID, number)
	if err != nil {
		return Detail{}, err
	}
	builds, err := s.store.ListBuilds(ctx, d.ID)
	if err != nil {
		return Detail{}, fmt.Errorf("list builds: %w", err)
	}
	out := Detail{Workspace: v.Workspace, App: app, Deployment: d, Builds: builds}
	inst, err := s.store.LatestInstanceOfDeployment(ctx, d.ID)
	if err == nil {
		out.Instance = &inst
	} else if !store.IsNotFound(err) {
		return Detail{}, fmt.Errorf("read instance: %w", err)
	}
	return out, nil
}

// LatestDeployment returns the app's newest deployment.
func (s *Service) LatestDeployment(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Detail, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return Detail{}, err
	}
	if app.NextDeploymentNumber <= 1 {
		return Detail{}, apperr.NotFound("the app has no deployments yet")
	}
	return s.GetDeployment(ctx, actor, wsSlug, appSlug, app.NextDeploymentNumber-1)
}

// ListDeployments returns deployments newest first, before the given
// number (0 for the first page).
func (s *Service) ListDeployments(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, before, limit int32) ([]store.Deployment, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return nil, err
	}
	if before <= 0 {
		before = app.NextDeploymentNumber
	}
	out, err := s.store.ListDeployments(ctx, store.ListDeploymentsParams{AppID: app.ID, BeforeNumber: before, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	return out, nil
}

// Cancel stops a deployment: one still waiting is canceled at once; a
// running build is asked to stop and ends as canceled shortly after.
func (s *Service) Cancel(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, number int32) (store.Deployment, error) {
	var out store.Deployment
	building := false
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		d, err := s.deployment(ctx, q, app.ID, number)
		if err != nil {
			return err
		}
		if d, err = q.LockDeployment(ctx, d.ID); err != nil {
			return fmt.Errorf("lock deployment: %w", err)
		}
		switch d.Status {
		case store.DeploymentStatusPending, store.DeploymentStatusUploading, store.DeploymentStatusQueued:
			out, err = q.CancelWaitingDeployment(ctx, store.CancelWaitingDeploymentParams{ID: d.ID, Reason: "canceled by a user"})
		case store.DeploymentStatusBuilding:
			building = true
			out, err = q.RequestCancel(ctx, d.ID)
		default:
			return apperr.Conflict("already_finished", "deployment #%d already finished (%s)", number, d.Status)
		}
		if err != nil {
			return fmt.Errorf("cancel deployment: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionDeploymentCancel, TargetType: audit.TargetDeployment, TargetID: d.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "number": number, "status": string(d.Status)},
		})
	})
	if err != nil {
		return store.Deployment{}, err
	}
	if building {
		s.queue.Wake(ctx, out.ID)
	}
	return out, nil
}
