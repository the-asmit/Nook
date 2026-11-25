-- Releases: deployments of built images, their rollouts and instances.

-- name: CreateReleaseDeployment :one
-- A deployment that releases an existing image again with another
-- environment (kind config) or an older deployment's environment (kind
-- rollback). It shares the source deployment's archive without owning it:
-- source_deleted_at is set so retention never deletes the archive twice.
INSERT INTO deployments (
    app_id, number, status, kind, image_of_deployment_id, rollback_to, env_snapshot_id,
    source_key, source_sha256, source_size, upload_expires_at, source_deleted_at,
    image_digest, created_by, built_at, enqueued_at
)
VALUES (
    @app_id, @number, 'built', @kind, @image_of_deployment_id, @rollback_to, @env_snapshot_id,
    @source_key, @source_sha256, @source_size, now(), now(),
    @image_digest, @created_by, now(), now()
)
RETURNING *;

-- name: StartDeploying :one
-- A built deployment starts its rollout; a build deployment takes the
-- environment snapshot made for it now.
UPDATE deployments
SET status = 'deploying', deploying_at = now(), env_snapshot_id = coalesce(env_snapshot_id, @env_snapshot_id)
WHERE id = @id AND status = 'built'
RETURNING *;

-- name: MarkLive :one
UPDATE deployments SET status = 'live', live_at = now(), failure_reason = ''
WHERE id = @id AND status = 'deploying'
RETURNING *;

-- name: RetireLive :many
-- The app's live deployment is replaced: superseded by a new release, or
-- rolled_back when the new release is a rollback.
UPDATE deployments
SET status = @status::deployment_status,
    superseded_at = CASE WHEN @status::deployment_status = 'superseded' THEN now() ELSE superseded_at END,
    rolled_back_at = CASE WHEN @status::deployment_status = 'rolled_back' THEN now() ELSE rolled_back_at END
WHERE app_id = @app_id AND status = 'live'
RETURNING id, number;

-- name: FailRollout :one
UPDATE deployments SET status = 'failed', failed_at = now(), failure_reason = @reason
WHERE id = @id AND status IN ('built', 'deploying')
RETURNING *;

-- name: SupersedeBuilt :one
-- A built deployment that will never be released because newer code is
-- already live.
UPDATE deployments SET status = 'superseded', superseded_at = now(), failure_reason = @reason
WHERE id = @id AND status = 'built'
RETURNING *;

-- name: NewerBuildReleased :one
SELECT EXISTS (
    SELECT 1 FROM deployments
    WHERE app_id = @app_id AND number > @number AND kind = 'build' AND live_at IS NOT NULL
) AS released;

-- name: LatestBuiltDeployment :one
SELECT * FROM deployments WHERE app_id = @app_id AND status = 'built' ORDER BY number DESC LIMIT 1;

-- name: GetLiveDeployment :one
SELECT * FROM deployments WHERE app_id = @app_id AND status = 'live';

-- name: DefaultRollbackTarget :one
-- The newest earlier deployment that was live once and still has its image.
SELECT * FROM deployments
WHERE app_id = @app_id AND number < @before_number AND live_at IS NOT NULL
  AND image_digest IS NOT NULL AND image_deleted_at IS NULL AND status <> 'live'
ORDER BY number DESC
LIMIT 1;

-- name: ListDeploymentsToConverge :many
-- Live deployments whose instances disagree with the app's desired state
-- and that were not queued recently: running apps without an instance
-- (unless one crashed or failed since the state was set), stopped or
-- deleted apps with instances still holding resources.
SELECT d.* FROM deployments d
JOIN apps a ON a.current_deployment_id = d.id
WHERE d.status = 'live' AND (d.enqueued_at IS NULL OR d.enqueued_at < @before)
  AND (
      ((a.desired_state = 'stopped' OR a.deleted_at IS NOT NULL) AND EXISTS (
          SELECT 1 FROM app_instances i
          WHERE i.deployment_id = d.id AND i.state IN ('starting', 'healthy', 'unhealthy', 'stopping')
      ))
      OR (a.desired_state = 'running' AND a.deleted_at IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM app_instances i
              WHERE i.deployment_id = d.id AND i.state IN ('starting', 'healthy', 'unhealthy', 'stopping')
          )
          AND NOT EXISTS (
              SELECT 1 FROM app_instances i
              WHERE i.deployment_id = d.id AND i.state IN ('crashed', 'failed') AND i.created_at >= a.desired_state_at
          ))
  )
ORDER BY d.created_at
LIMIT @row_limit;

-- Scheduling.

-- name: LockSchedulableNodes :many
-- Every node that may receive an app, locked in a fixed order: concurrent
-- placements serialize here, so two of them can never both take the last
-- free capacity of a node.
SELECT id, name, memory_total_bytes, cpu_count, advertise_address FROM nodes
WHERE status = 'ready' AND NOT draining AND removed_at IS NULL AND advertise_address <> ''
ORDER BY id
FOR UPDATE;

-- name: NodeReservations :many
-- What instances holding resources reserve on each node.
SELECT node_id,
       sum(memory_mb)::bigint AS memory_mb,
       sum(cpu_millicores)::bigint AS cpu_millicores,
       count(*)::integer AS instances
FROM app_instances
WHERE node_id IS NOT NULL AND state IN ('starting', 'healthy', 'unhealthy', 'stopping')
GROUP BY node_id;

-- name: WorkspaceReservedMemory :one
-- Memory reserved by a workspace's instances, not counting one app (whose
-- old and new versions overlap during a rollout).
SELECT coalesce(sum(memory_mb), 0)::bigint AS memory_mb FROM app_instances
WHERE workspace_id = @workspace_id AND app_id <> @except_app_id
  AND state IN ('starting', 'healthy', 'unhealthy', 'stopping');

-- Instances.

-- name: CreateInstance :one
INSERT INTO app_instances (app_id, deployment_id, workspace_id, node_id, node_name, memory_mb, cpu_millicores, address)
VALUES (@app_id, @deployment_id, @workspace_id, @node_id, @node_name, @memory_mb, @cpu_millicores, @address)
RETURNING *;

-- name: GetInstance :one
SELECT * FROM app_instances WHERE id = @id;

-- name: LatestInstanceOfDeployment :one
SELECT * FROM app_instances WHERE deployment_id = @deployment_id ORDER BY created_at DESC LIMIT 1;

-- name: ListReservedInstancesOfApp :many
SELECT * FROM app_instances
WHERE app_id = @app_id AND state IN ('starting', 'healthy', 'unhealthy', 'stopping')
ORDER BY created_at;

-- name: ListInstancesOnNode :many
-- Instances whose containers a node should have: running, stopping, or
-- crashed (kept for their logs).
SELECT * FROM app_instances
WHERE node_id = @node_id AND state IN ('starting', 'healthy', 'unhealthy', 'stopping', 'crashed')
ORDER BY created_at;

-- name: LatestInstanceOfApp :one
SELECT * FROM app_instances WHERE app_id = @app_id ORDER BY created_at DESC LIMIT 1;

-- name: LatestInstanceWithContainer :one
-- The newest instance whose container may still exist, for `nook logs`.
SELECT * FROM app_instances
WHERE app_id = @app_id AND container_id IS NOT NULL AND state IN ('starting', 'healthy', 'unhealthy', 'stopping', 'crashed')
ORDER BY created_at DESC
LIMIT 1;

-- name: MarkInstanceStartSent :exec
UPDATE app_instances SET start_sent_at = now(), updated_at = now() WHERE id = @id;

-- name: InstanceRunning :one
-- The agent reports the container started (or restarted) and passed its
-- health check.
UPDATE app_instances
SET state = 'healthy', container_id = @container_id, host_port = @host_port, restart_count = @restart_count,
    started_at = coalesce(started_at, now()), last_healthy_at = now(), last_error = '', updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy')
RETURNING *;

-- name: InstanceUnhealthy :one
-- The container crashed and the agent restarts it after a backoff.
UPDATE app_instances
SET state = 'unhealthy', restart_count = @restart_count, last_error = @last_error, updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy')
RETURNING *;

-- name: InstanceCrashed :one
-- The container crashed too often: the agent stopped restarting it.
UPDATE app_instances
SET state = 'crashed', restart_count = @restart_count, last_error = @last_error, stopped_at = now(), updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy')
RETURNING *;

-- name: InstanceFailed :one
-- The instance never became healthy (image pull, start or health check).
UPDATE app_instances
SET state = 'failed', last_error = @last_error, startup_log = @startup_log, stopped_at = now(), updated_at = now()
WHERE id = @id AND state IN ('starting', 'unhealthy')
RETURNING *;

-- name: RequestInstanceStop :one
UPDATE app_instances SET state = 'stopping', stop_requested_at = now(), updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy', 'crashed')
RETURNING *;

-- name: InstanceStopped :one
UPDATE app_instances SET state = 'stopped', stopped_at = coalesce(stopped_at, now()), updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy', 'stopping', 'crashed')
RETURNING *;

-- name: SetInstanceContainer :exec
-- The agent created the container (reported before it is healthy).
UPDATE app_instances SET container_id = @container_id, host_port = @host_port, updated_at = now()
WHERE id = @id;

-- Environment variables.

-- name: ListAppEnv :many
SELECT * FROM app_env WHERE app_id = @app_id ORDER BY key;

-- name: UpsertAppEnv :exec
INSERT INTO app_env (app_id, key, value, key_version, is_secret, updated_by, updated_at)
VALUES (@app_id, @key, @value, @key_version, @is_secret, @updated_by, now())
ON CONFLICT (app_id, key) DO UPDATE
SET value = EXCLUDED.value, key_version = EXCLUDED.key_version, is_secret = EXCLUDED.is_secret,
    updated_by = EXCLUDED.updated_by, updated_at = now();

-- name: DeleteAppEnv :execrows
DELETE FROM app_env WHERE app_id = @app_id AND key = @key;

-- name: CreateEnvSnapshot :one
INSERT INTO env_snapshots (app_id, created_by) VALUES (@app_id, @created_by) RETURNING *;

-- name: CopyEnvToSnapshot :exec
-- Snapshots copy the ciphertexts as they are: values are bound to the app
-- and key, not to the row that holds them.
INSERT INTO env_snapshot_vars (snapshot_id, key, value, key_version, is_secret)
SELECT @snapshot_id, key, value, key_version, is_secret FROM app_env WHERE app_id = @app_id;

-- name: ListSnapshotVars :many
SELECT * FROM env_snapshot_vars WHERE snapshot_id = @snapshot_id ORDER BY key;

-- Master-key rotation.

-- name: ListAppEnvNotOnVersion :many
SELECT app_id, key, value, key_version FROM app_env
WHERE key_version <> @version
ORDER BY app_id, key
LIMIT @row_limit;

-- name: ReencryptAppEnv :execrows
UPDATE app_env SET value = @value, key_version = @key_version
WHERE app_id = @app_id AND key = @key AND key_version = @old_version;

-- name: ListSnapshotVarsNotOnVersion :many
SELECT v.snapshot_id, s.app_id, v.key, v.value, v.key_version
FROM env_snapshot_vars v JOIN env_snapshots s ON s.id = v.snapshot_id
WHERE v.key_version <> @version
ORDER BY v.snapshot_id, v.key
LIMIT @row_limit;

-- name: ReencryptSnapshotVar :execrows
UPDATE env_snapshot_vars SET value = @value, key_version = @key_version
WHERE snapshot_id = @snapshot_id AND key = @key AND key_version = @old_version;

-- name: KeyVersionsInUse :many
SELECT key_version FROM app_env
UNION
SELECT key_version FROM env_snapshot_vars
ORDER BY 1;

-- name: ListSecretKeyChecks :many
SELECT * FROM secret_key_checks ORDER BY version;

-- name: InsertSecretKeyCheck :exec
INSERT INTO secret_key_checks (version, check_value) VALUES (@version, @check_value)
ON CONFLICT (version) DO NOTHING;
