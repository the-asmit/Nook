-- name: GetWorkspaceQuota :one
SELECT * FROM workspace_quotas WHERE workspace_id = @workspace_id;

-- name: UpsertWorkspaceQuota :one
INSERT INTO workspace_quotas (workspace_id, max_apps, max_concurrent_builds, updated_by, updated_at)
VALUES (@workspace_id, @max_apps, @max_concurrent_builds, @updated_by, now())
ON CONFLICT (workspace_id) DO UPDATE
SET max_apps = EXCLUDED.max_apps, max_concurrent_builds = EXCLUDED.max_concurrent_builds,
    updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING *;

-- name: GetWorkspaceBySlug :one
-- Instance administrators manage quotas of any workspace.
SELECT * FROM workspaces WHERE slug = @slug;

-- name: CountLiveApps :one
SELECT count(*) FROM apps WHERE workspace_id = @workspace_id AND deleted_at IS NULL;

-- name: CountApps :one
-- Includes deleted apps whose images and data are not purged yet.
SELECT count(*) FROM apps WHERE workspace_id = @workspace_id;

-- name: CreateApp :one
INSERT INTO apps (workspace_id, slug, name, created_by, port, health_check_path, memory_mb, cpu_millicores)
VALUES (@workspace_id, @slug, @name, @created_by, @port, @health_check_path, @memory_mb, @cpu_millicores)
RETURNING *;

-- name: GetApp :one
-- Live app by slug within a workspace the caller already resolved through
-- their membership.
SELECT * FROM apps WHERE workspace_id = @workspace_id AND slug = @slug AND deleted_at IS NULL;

-- name: GetAppByID :one
SELECT * FROM apps WHERE id = @id;

-- name: ListApps :many
SELECT * FROM apps
WHERE workspace_id = @workspace_id AND deleted_at IS NULL AND slug > @after_slug
ORDER BY slug
LIMIT @row_limit;

-- name: NextDeploymentNumber :one
-- Takes the next number under the app row's lock (concurrent deploys
-- queue up here and get consecutive numbers).
UPDATE apps SET next_deployment_number = next_deployment_number + 1
WHERE id = @id AND deleted_at IS NULL
RETURNING (next_deployment_number - 1)::integer AS number;

-- name: SoftDeleteApp :one
UPDATE apps SET deleted_at = now() WHERE id = @id AND deleted_at IS NULL RETURNING *;

-- name: ListDeletedApps :many
SELECT * FROM apps WHERE deleted_at IS NOT NULL ORDER BY deleted_at LIMIT @row_limit;

-- name: PurgeApp :exec
-- Removes a deleted app with its deployments and builds once its images,
-- sources and logs are gone.
DELETE FROM apps WHERE id = @id AND deleted_at IS NOT NULL;

-- name: CreateDeployment :one
INSERT INTO deployments (app_id, number, status, source_key, source_sha256, source_size, upload_expires_at, created_by)
VALUES (@app_id, @number, 'pending', @source_key, @source_sha256, @source_size, @upload_expires_at, @created_by)
RETURNING *;

-- name: MarkDeploymentUploading :one
UPDATE deployments SET status = 'uploading', uploading_at = now()
WHERE id = @id AND status = 'pending'
RETURNING *;

-- name: GetDeployment :one
SELECT * FROM deployments WHERE app_id = @app_id AND number = @number;

-- name: GetDeploymentByID :one
SELECT * FROM deployments WHERE id = @id;

-- name: LockDeployment :one
SELECT * FROM deployments WHERE id = @id FOR UPDATE;

-- name: ListDeployments :many
SELECT * FROM deployments
WHERE app_id = @app_id AND number < @before_number
ORDER BY number DESC
LIMIT @row_limit;

-- name: QueueDeployment :one
-- The upload was verified: the deployment enters the build queue.
UPDATE deployments SET status = 'queued', queued_at = now(), enqueued_at = now()
WHERE id = @id AND status IN ('pending', 'uploading')
RETURNING *;

-- name: NewerQueuedExists :one
SELECT EXISTS (
    SELECT 1 FROM deployments
    WHERE app_id = @app_id AND number > @number AND status = 'queued'
) AS newer;

-- name: SupersedeQueued :many
-- A newer deploy replaces older ones still waiting in the queue.
UPDATE deployments
SET status = 'cancelled', cancelled_at = now(), failure_reason = @reason
WHERE app_id = @app_id AND number < @number AND status = 'queued'
RETURNING id, number;

-- name: CancelWaitingDeployment :one
-- Cancels a deployment that has not started building.
UPDATE deployments
SET status = 'cancelled', cancelled_at = now(), failure_reason = @reason
WHERE id = @id AND status IN ('pending', 'uploading', 'queued')
RETURNING *;

-- name: RequestCancel :one
UPDATE deployments SET cancel_requested_at = coalesce(cancel_requested_at, now())
WHERE id = @id AND status = 'building'
RETURNING *;

-- name: MarkEnqueued :exec
UPDATE deployments SET enqueued_at = now() WHERE id = @id;

-- name: StartBuilding :one
UPDATE deployments SET status = 'building', building_at = coalesce(building_at, now())
WHERE id = @id AND status = 'queued'
RETURNING *;

-- name: RequeueDeployment :one
-- An attempt failed for infrastructure reasons; the deployment waits for
-- another node.
UPDATE deployments SET status = 'queued'
WHERE id = @id AND status = 'building'
RETURNING *;

-- name: MarkBuilt :one
UPDATE deployments SET status = 'built', built_at = now(), image_digest = @image_digest
WHERE id = @id AND status = 'building'
RETURNING *;

-- name: MarkFailed :one
UPDATE deployments SET status = 'failed', failed_at = now(), failure_reason = @reason
WHERE id = @id AND status IN ('pending', 'uploading', 'queued', 'building')
RETURNING *;

-- name: MarkCancelled :one
UPDATE deployments SET status = 'cancelled', cancelled_at = now(), failure_reason = @reason
WHERE id = @id AND status IN ('queued', 'building')
RETURNING *;

-- name: ListUnownedActiveDeployments :many
-- Queued or building deployments not re-added to the queue recently; the
-- janitor re-enqueues them in case their queue entry was lost.
SELECT * FROM deployments
WHERE status IN ('queued', 'building') AND (enqueued_at IS NULL OR enqueued_at < @before)
ORDER BY created_at
LIMIT @row_limit;

-- name: ListAbandonedUploads :many
SELECT * FROM deployments
WHERE status IN ('pending', 'uploading') AND upload_expires_at < @before
ORDER BY created_at
LIMIT @row_limit;

-- name: ListImagesBeyondRetention :many
-- Built images beyond the newest @keep per app, oldest first.
SELECT id, app_id, number, image_digest FROM (
    SELECT d.id, d.app_id, d.number, d.image_digest,
           row_number() OVER (PARTITION BY d.app_id ORDER BY d.number DESC) AS rank
    FROM deployments d
    WHERE d.status = 'built' AND d.image_deleted_at IS NULL
) ranked
WHERE rank > @keep::bigint
ORDER BY number
LIMIT @row_limit;

-- name: ListImagesOfApp :many
SELECT id, number, image_digest FROM deployments
WHERE app_id = @app_id AND image_digest IS NOT NULL AND image_deleted_at IS NULL;

-- name: MarkImageDeleted :exec
UPDATE deployments SET image_deleted_at = now() WHERE id = @id;

-- name: ListExpiredSources :many
-- Source archives of finished deployments older than the retention window.
SELECT id, source_key FROM deployments
WHERE source_deleted_at IS NULL AND created_at < @before
  AND status IN ('built', 'failed', 'cancelled')
LIMIT @row_limit;

-- name: ListSourcesOfApp :many
SELECT id, source_key FROM deployments WHERE app_id = @app_id AND source_deleted_at IS NULL;

-- name: MarkSourceDeleted :exec
UPDATE deployments SET source_deleted_at = now() WHERE id = @id;

-- name: IsRecordedImage :one
-- Whether a digest is the image of a deployment (so it must not be
-- garbage-collected as a stray push).
SELECT EXISTS (
    SELECT 1 FROM deployments WHERE app_id = @app_id AND image_digest = @image_digest AND image_deleted_at IS NULL
) AS recorded;
