-- name: CreateJoinToken :one
INSERT INTO join_tokens (token_hash, prefix, created_by, expires_at, max_uses)
VALUES (@token_hash, @prefix, @created_by, now() + make_interval(secs => @ttl_seconds::float8), @max_uses)
RETURNING *;

-- name: ConsumeJoinToken :one
-- Atomically uses one of the token's uses; no row means the token is
-- unknown, expired, revoked or used up, which callers must not distinguish.
UPDATE join_tokens
SET uses = uses + 1, last_used_at = now()
WHERE token_hash = @token_hash
  AND revoked_at IS NULL
  AND expires_at > now()
  AND uses < max_uses
RETURNING id;

-- name: ListJoinTokens :many
-- Usable tokens and those that ended in the last day, newest first.
SELECT * FROM join_tokens
WHERE id < @before_id
  AND (revoked_at IS NULL OR revoked_at > now() - interval '1 day')
  AND expires_at > now() - interval '1 day'
ORDER BY id DESC
LIMIT @row_limit;

-- name: RevokeJoinToken :one
UPDATE join_tokens SET revoked_at = now()
WHERE id = @id AND revoked_at IS NULL
RETURNING *;

-- name: CreateNode :one
INSERT INTO nodes (name, labels, hostname, addresses, cpu_count, memory_total_bytes, disk_total_bytes,
                   docker_version, agent_version, os, arch, joined_with_token_id)
VALUES (@name, @labels, @hostname, @addresses, @cpu_count, @memory_total_bytes, @disk_total_bytes,
        @docker_version, @agent_version, @os, @arch, @joined_with_token_id)
RETURNING *;

-- name: UpdateNodeInfo :exec
-- Refreshes what the agent reports about itself on every connection.
UPDATE nodes
SET hostname = @hostname, addresses = @addresses, cpu_count = @cpu_count,
    memory_total_bytes = @memory_total_bytes, disk_total_bytes = @disk_total_bytes,
    docker_version = @docker_version, agent_version = @agent_version, os = @os, arch = @arch,
    build_slots = @build_slots, advertise_address = @advertise_address,
    builds_unavailable_reason = @builds_unavailable_reason,
    db_address = @db_address, db_publish_address = @db_publish_address, db_port = @db_port,
    db_unavailable_reason = @db_unavailable_reason
WHERE id = @id AND removed_at IS NULL;

-- name: InsertNodeCertificate :exec
INSERT INTO node_certificates (serial, node_id, not_before, not_after)
VALUES (@serial, @node_id, @not_before, @not_after);

-- name: GetNodeCertificate :one
-- Checked on every new agent connection.
SELECT c.serial, c.node_id, c.not_after, c.revoked_at, n.status AS node_status, n.name AS node_name
FROM node_certificates c
JOIN nodes n ON n.id = c.node_id
WHERE c.serial = @serial;

-- name: RevokeNodeCertificate :execrows
UPDATE node_certificates SET revoked_at = now() WHERE serial = @serial AND revoked_at IS NULL;

-- name: RevokeNodeCertificates :execrows
UPDATE node_certificates SET revoked_at = now() WHERE node_id = @node_id AND revoked_at IS NULL;

-- name: PersistHeartbeat :exec
UPDATE nodes
SET last_heartbeat_at = @received_at,
    memory_available_bytes = @memory_available_bytes,
    cpu_load_1m = @cpu_load_1m,
    disk_free_bytes = @disk_free_bytes,
    running_containers = @running_containers,
    docker_reachable = @docker_reachable,
    agent_version = @agent_version
WHERE id = @id AND removed_at IS NULL
  AND (last_heartbeat_at IS NULL OR last_heartbeat_at < @received_at);

-- name: ListLiveNodes :many
-- The failure detector's view: every node that has not been removed.
SELECT id, name, status, draining, joined_at, last_heartbeat_at
FROM nodes
WHERE removed_at IS NULL
ORDER BY id;

-- name: TransitionNode :execrows
-- Compare-and-set, so a health transition never overwrites a concurrent
-- admin action (drain, removal) or another transition. The latest
-- heartbeat time is persisted with every state change.
UPDATE nodes
SET status = @to_status,
    last_heartbeat_at = GREATEST(last_heartbeat_at, sqlc.narg(seen_at)::timestamptz)
WHERE id = @id AND status = @from_status AND removed_at IS NULL;

-- name: InsertNodeEvent :one
INSERT INTO node_events (node_id, from_status, to_status, reason)
VALUES (@node_id, @from_status, @to_status, @reason)
RETURNING *;

-- name: ListNodes :many
SELECT * FROM nodes
WHERE removed_at IS NULL AND name > @after_name
ORDER BY name
LIMIT @row_limit;

-- name: GetLiveNodeByName :one
SELECT * FROM nodes WHERE name = @name AND removed_at IS NULL;

-- name: GetLiveNodeByID :one
SELECT * FROM nodes WHERE id = @id AND removed_at IS NULL;

-- name: LockLiveNode :one
SELECT * FROM nodes WHERE id = @id AND removed_at IS NULL FOR UPDATE;

-- name: SetNodeDraining :exec
UPDATE nodes SET draining = @draining, status = @status WHERE id = @id AND removed_at IS NULL;

-- name: RemoveNode :exec
UPDATE nodes SET status = 'removed', removed_at = now(), draining = false
WHERE id = @id AND removed_at IS NULL;

-- name: ListNodeEvents :many
SELECT * FROM node_events WHERE node_id = @node_id ORDER BY id DESC LIMIT @row_limit;

-- name: SetNodeLabels :exec
UPDATE nodes SET labels = @labels WHERE id = @id AND removed_at IS NULL;
