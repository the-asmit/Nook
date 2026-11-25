-- name: CreateBuild :one
INSERT INTO builds (deployment_id, app_id, workspace_id, node_id, node_name, attempt, image_tag)
VALUES (@deployment_id, @app_id, @workspace_id, @node_id, @node_name, @attempt, @image_tag)
RETURNING *;

-- name: GetBuild :one
SELECT * FROM builds WHERE id = @id;

-- name: GetActiveBuild :one
SELECT * FROM builds WHERE deployment_id = @deployment_id AND finished_at IS NULL;

-- name: LastBuild :one
SELECT * FROM builds WHERE deployment_id = @deployment_id ORDER BY attempt DESC LIMIT 1;

-- name: ListBuilds :many
SELECT * FROM builds WHERE deployment_id = @deployment_id ORDER BY attempt;

-- name: NodesTriedForDeployment :many
SELECT DISTINCT node_id FROM builds WHERE deployment_id = @deployment_id AND node_id IS NOT NULL;

-- name: MarkBuildStarted :one
UPDATE builds SET started_at = coalesce(started_at, now())
WHERE id = @id AND finished_at IS NULL
RETURNING *;

-- name: FinishBuild :one
-- Exactly one outcome per build: later reports find finished_at set.
UPDATE builds
SET finished_at = now(), result = @result, message = @message,
    image_digest = sqlc.narg(image_digest), log_bytes = sqlc.narg(log_bytes)
WHERE id = @id AND finished_at IS NULL
RETURNING *;

-- name: SetBuildLogKey :exec
UPDATE builds SET log_key = @log_key WHERE id = @id;

-- name: ClearBuildLogKey :exec
UPDATE builds SET log_key = NULL WHERE id = @id;

-- name: MarkCancelSent :exec
UPDATE builds SET cancel_sent_at = now() WHERE id = @id;

-- name: ListActiveBuildsOnNode :many
SELECT * FROM builds WHERE node_id = @node_id AND finished_at IS NULL;

-- name: CountActiveBuildsByNode :many
SELECT node_id, count(*)::integer AS active FROM builds
WHERE finished_at IS NULL AND node_id IS NOT NULL
GROUP BY node_id;

-- name: CountActiveBuildsInWorkspace :one
SELECT count(*)::integer FROM builds WHERE workspace_id = @workspace_id AND finished_at IS NULL;

-- name: ListBuildNodes :many
-- Nodes that may receive builds: ready, not draining, with build slots
-- and able to run rootless BuildKit.
SELECT id, name, build_slots, memory_available_bytes FROM nodes
WHERE status = 'ready' AND NOT draining AND removed_at IS NULL AND build_slots > 0
  AND builds_unavailable_reason = '';

-- name: GetNodeStatus :one
SELECT status FROM nodes WHERE id = @id;

-- name: ListExpiredLogs :many
SELECT id, log_key FROM builds
WHERE log_key IS NOT NULL AND finished_at < @before
LIMIT @row_limit;

-- name: ListLogsOfApp :many
SELECT id, log_key FROM builds WHERE app_id = @app_id AND log_key IS NOT NULL;

-- name: CountActiveBuilds :one
-- Builds that may be pushing to the registry right now.
SELECT count(*)::integer FROM builds WHERE finished_at IS NULL;

-- name: DeleteUnstartedBuild :execrows
-- Withdraws a build that was placed but never handed to a node.
DELETE FROM builds WHERE id = @id AND started_at IS NULL AND finished_at IS NULL;
