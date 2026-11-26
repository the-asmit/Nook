-- Sleep, wake, eviction, failover and draining.

-- name: SleepApp :one
-- Puts a running app to sleep (the one transition that may, so an app is
-- never put to sleep twice). Only the live deployment's app qualifies.
UPDATE apps
SET sleeping_since = now(), sleep_reason = @reason, last_request_at = @last_request_at, wake_requested_at = NULL
WHERE id = @id AND sleeping_since IS NULL AND deleted_at IS NULL AND desired_state = 'running'
  AND current_deployment_id = @deployment_id
RETURNING *;

-- name: SleepInstance :one
-- The instance of a sleeping app: its container stops (and is kept) and its
-- reservation is released at once.
UPDATE app_instances
SET state = 'sleeping', stop_requested_at = now(), stop_reason = @stop_reason, updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy')
RETURNING *;

-- name: WakeApp :one
-- The compare-and-set that makes exactly one wake happen, however many
-- gateways and requests ask at once.
UPDATE apps
SET sleeping_since = NULL, sleep_reason = '', wake_requested_at = now()
WHERE id = @id AND sleeping_since IS NOT NULL AND deleted_at IS NULL
RETURNING *;

-- name: ClearSleep :exec
-- The app is started, stopped or released anew: whether it slept no longer
-- matters.
UPDATE apps SET sleeping_since = NULL, sleep_reason = '', wake_requested_at = NULL
WHERE id = @id AND (sleeping_since IS NOT NULL OR wake_requested_at IS NOT NULL);

-- name: WakeDone :exec
-- The woken instance is healthy.
UPDATE apps SET wake_requested_at = NULL WHERE id = @id AND wake_requested_at IS NOT NULL;

-- name: SleepingInstanceOfApp :one
SELECT * FROM app_instances WHERE app_id = @app_id AND state = 'sleeping';

-- name: ResumeInstance :one
-- A sleeping instance starts again on its node (its container and image are
-- still there).
UPDATE app_instances
SET state = 'starting', start_sent_at = NULL, stop_requested_at = NULL, stopped_at = NULL, stop_reason = '',
    cause = @cause, cause_at = @cause_at, last_error = '', startup_log = '', updated_at = now()
WHERE id = @id AND state = 'sleeping'
RETURNING *;

-- name: FinishSleepingInstance :one
-- A sleeping instance that will not wake on its node: its container goes.
UPDATE app_instances SET state = 'stopped', stopped_at = now(), updated_at = now()
WHERE id = @id AND state = 'sleeping'
RETURNING *;

-- name: SetInstanceCause :exec
UPDATE app_instances SET cause = @cause, cause_at = @cause_at, updated_at = now() WHERE id = @id;

-- name: ListIdleCandidates :many
-- Running apps that may sleep: a healthy instance of the live deployment,
-- nothing else starting, a sleep_after. Activity comes from Redis.
SELECT a.id AS app_id, a.slug, a.workspace_id, a.sleep_after_seconds, a.current_deployment_id, a.last_request_at,
       i.id AS instance_id, i.last_healthy_at
FROM apps a
JOIN app_instances i ON i.deployment_id = a.current_deployment_id AND i.state = 'healthy'
WHERE a.deleted_at IS NULL AND a.desired_state = 'running' AND a.sleeping_since IS NULL
  AND a.sleep_after_seconds IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM app_instances s WHERE s.app_id = a.id AND s.state = 'starting')
ORDER BY a.id;

-- name: ListEvictable :many
-- Healthy instances on schedulable nodes whose apps may be put to sleep to
-- make room (not apps with sleep_after = never, not the app being placed).
SELECT i.id AS instance_id, i.app_id, i.deployment_id, i.node_id, i.memory_mb, i.cpu_millicores, i.last_healthy_at,
       a.slug, a.workspace_id, a.last_request_at
FROM app_instances i
JOIN apps a ON a.id = i.app_id AND a.current_deployment_id = i.deployment_id
JOIN nodes n ON n.id = i.node_id
WHERE i.state = 'healthy' AND a.deleted_at IS NULL AND a.desired_state = 'running' AND a.sleeping_since IS NULL
  AND a.sleep_after_seconds IS NOT NULL AND a.id <> @except_app_id
  AND n.status = 'ready' AND NOT n.draining AND n.removed_at IS NULL
ORDER BY i.node_id, i.id;

-- name: CountSleepingApps :one
-- Apps asleep and the memory their reservations released.
SELECT count(*)::bigint AS apps, coalesce(sum(memory_mb), 0)::bigint AS memory_mb
FROM apps WHERE sleeping_since IS NOT NULL AND deleted_at IS NULL;

-- name: CountRunningApps :one
SELECT count(DISTINCT app_id)::bigint FROM app_instances WHERE state IN ('starting', 'healthy', 'unhealthy');

-- name: ListDeploymentInstances :many
-- A deployment's instances that are not finished, with their node's state.
SELECT sqlc.embed(i), coalesce(n.status::text, 'removed')::text AS node_status, coalesce(n.draining, false)::boolean AS node_draining
FROM app_instances i
LEFT JOIN nodes n ON n.id = i.node_id
WHERE i.deployment_id = @deployment_id AND i.state IN ('starting', 'healthy', 'unhealthy', 'stopping', 'sleeping')
ORDER BY i.created_at;

-- name: LatestStoppedInstanceOfDeployment :one
-- The most recent instance of a deployment that stopped or is stopping
-- (why it stopped tells why a new one is needed).
SELECT * FROM app_instances
WHERE deployment_id = @deployment_id AND state IN ('stopping', 'stopped') AND stop_requested_at IS NOT NULL
ORDER BY stop_requested_at DESC
LIMIT 1;

-- name: ListInstancesOnDeadNodes :many
-- Instances that still count as running on nodes the failure detector
-- declared dead, with the time of the node's death.
SELECT i.id, i.app_id, i.deployment_id, i.node_name,
       coalesce((SELECT max(e.created_at) FROM node_events e WHERE e.node_id = i.node_id AND e.to_status = 'dead'), now())::timestamptz AS dead_at
FROM app_instances i
JOIN nodes n ON n.id = i.node_id
WHERE n.status = 'dead' AND i.state IN ('starting', 'healthy', 'unhealthy')
ORDER BY i.id
LIMIT @row_limit;

-- name: ListFailedOverOnLiveNodes :many
-- Failed-over instances whose node is alive again. Reconciliation removes
-- their containers when the agent reconnects, but a node can come back
-- without reconnecting (late heartbeats on an intact stream, or a
-- reconnect just before the failover), so the leader sends the stop.
SELECT i.* FROM app_instances i
JOIN nodes n ON n.id = i.node_id
WHERE i.state = 'stopping' AND i.stop_reason = 'failover' AND n.status IN ('ready', 'suspect', 'draining')
ORDER BY i.id
LIMIT @row_limit;

-- name: FailOverInstance :one
-- An instance on a dead node no longer serves; the time it stopped
-- serving is the node's death.
UPDATE app_instances
SET state = 'stopping', stop_requested_at = @dead_at, stop_reason = 'failover', updated_at = now()
WHERE id = @id AND state IN ('starting', 'healthy', 'unhealthy')
RETURNING *;

-- name: ListDeploymentsOnDrainingNodes :many
-- Live deployments with an instance on a draining node: they move.
SELECT DISTINCT i.deployment_id
FROM app_instances i
JOIN nodes n ON n.id = i.node_id
JOIN apps a ON a.current_deployment_id = i.deployment_id AND a.deleted_at IS NULL
WHERE n.draining AND n.removed_at IS NULL AND i.state IN ('starting', 'healthy', 'unhealthy')
LIMIT @row_limit;

-- name: ListSleepingOnDrainingNodes :many
-- Kept containers of sleeping apps on draining nodes: removed (the apps
-- wake elsewhere).
SELECT i.* FROM app_instances i
JOIN nodes n ON n.id = i.node_id
WHERE n.draining AND n.removed_at IS NULL AND i.state = 'sleeping'
LIMIT @row_limit;

-- name: NodeDeadAt :one
-- When a node was last declared dead.
SELECT coalesce(max(created_at), now())::timestamptz FROM node_events WHERE node_id = @node_id AND to_status = 'dead';

-- name: CountActiveInstancesOnNode :one
-- Instances that still run (or are stopping) on a node: zero when a drain
-- is complete.
SELECT count(*)::bigint FROM app_instances
WHERE node_id = @node_id AND state IN ('starting', 'healthy', 'unhealthy', 'stopping');
