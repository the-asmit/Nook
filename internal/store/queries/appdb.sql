-- App database servers (one current generation per installation).

-- name: CurrentDBServer :one
SELECT * FROM app_db_servers WHERE state IN ('starting', 'running', 'stopping');

-- name: LatestDBServer :one
SELECT * FROM app_db_servers ORDER BY generation DESC LIMIT 1;

-- name: GetDBServer :one
SELECT * FROM app_db_servers WHERE id = @id;

-- name: ListDBServers :many
SELECT * FROM app_db_servers ORDER BY generation DESC LIMIT @row_limit;

-- name: CreateDBServer :one
-- The ID comes from the caller: the superuser password is sealed bound to it.
INSERT INTO app_db_servers (id, generation, mode, cause, cause_at, node_id, node_name, memory_mb,
                            superuser_password, password_key_version, backup_key_version)
VALUES (@id, @generation, @mode, @cause, @cause_at, @node_id, @node_name, @memory_mb,
        @superuser_password, @password_key_version, @backup_key_version)
RETURNING *;

-- name: DBServerStartSent :exec
UPDATE app_db_servers SET start_sent_at = now(), tls_expires_at = @tls_expires_at, updated_at = now()
WHERE id = @id AND state = 'starting';

-- name: DBServerRunning :one
-- The compare-and-set that makes a starting server current for apps.
UPDATE app_db_servers
SET state = 'running', address = @address, port = @port, running_at = now(), last_error = '', updated_at = now()
WHERE id = @id AND state = 'starting'
RETURNING *;

-- name: DBServerFailed :one
UPDATE app_db_servers SET state = 'failed', last_error = @last_error, updated_at = now()
WHERE id = @id AND state IN ('starting', 'running')
RETURNING *;

-- name: FenceDBServer :one
-- The server is replaced: apps never use it again, its container must
-- not run (its volume stays until an admin removes it).
UPDATE app_db_servers SET state = 'fenced', fenced_at = now(), updated_at = now()
WHERE id = @id AND state IN ('starting', 'running', 'stopping')
RETURNING *;

-- name: DBServerStopping :one
-- A planned failover begins: clean shutdown and final archive.
UPDATE app_db_servers
SET state = 'stopping', move_to_node_id = @move_to_node_id, stop_requested_at = now(), updated_at = now()
WHERE id = @id AND state = 'running'
RETURNING *;

-- name: DBServerStopSent :exec
UPDATE app_db_servers SET stop_sent_at = now() WHERE id = @id AND state = 'stopping';

-- name: DBServerRestarting :one
-- A running server's container exited on a live node: start it again on
-- its own volume.
UPDATE app_db_servers SET state = 'starting', start_sent_at = NULL, last_error = @last_error, updated_at = now()
WHERE id = @id AND state = 'running'
RETURNING *;

-- name: AnyDBServerRan :one
-- Whether a server ever ran (and so backups may exist to restore).
SELECT EXISTS (SELECT 1 FROM app_db_servers WHERE running_at IS NOT NULL);

-- name: DBServerStopped :one
-- The stopping server shut down cleanly and archived everything.
UPDATE app_db_servers
SET state = 'fenced', final_wal = @final_wal, stopped_at = now(), fenced_at = now(), updated_at = now()
WHERE id = @id AND state = 'stopping'
RETURNING *;

-- name: DBServerContainerStopped :exec
-- A replaced or failed server's container is confirmed stopped.
UPDATE app_db_servers SET stopped_at = coalesce(stopped_at, now()), updated_at = now()
WHERE id = @id AND state IN ('fenced', 'failed');

-- name: MarkDBServerRemoved :one
UPDATE app_db_servers SET state = 'removed', removed_at = now(), stopped_at = coalesce(stopped_at, now()), updated_at = now()
WHERE id = @id AND state IN ('fenced', 'failed')
RETURNING *;

-- name: ListUnstoppedOldDBServers :many
-- Replaced or failed servers whose container may still run, on nodes
-- whose agents can be told to stop it (fencing).
SELECT * FROM app_db_servers s
WHERE s.state IN ('fenced', 'failed') AND s.stopped_at IS NULL
  AND EXISTS (SELECT 1 FROM nodes n WHERE n.id = s.node_id
              AND n.status IN ('ready', 'suspect', 'draining') AND n.removed_at IS NULL)
ORDER BY s.generation;

-- name: CurrentDBServerHealth :one
-- The current server with its node's state and, if the node died, when.
SELECT sqlc.embed(s), coalesce(n.status::text, 'removed')::text AS node_status, coalesce(n.draining, false) AS node_draining,
       coalesce((SELECT max(e.created_at) FROM node_events e WHERE e.node_id = s.node_id AND e.to_status = 'dead'), now())::timestamptz AS dead_at
FROM app_db_servers s
LEFT JOIN nodes n ON n.id = s.node_id AND n.removed_at IS NULL
WHERE s.state IN ('starting', 'running', 'stopping');

-- name: SetDBServerMonitor :exec
UPDATE app_db_servers
SET checked_at = now(), archived_count = @archived_count, last_archived_wal = @last_archived_wal,
    last_archived_at = @last_archived_at, archive_failed_count = @archive_failed_count,
    last_failed_wal = @last_failed_wal, last_failed_at = @last_failed_at,
    databases_size_bytes = @databases_size_bytes, connections = @connections
WHERE id = @id;

-- name: DBServerBackupStarted :one
-- Claims the next base backup (none may be running, or the last claim is
-- stale).
UPDATE app_db_servers SET backup_started_at = now(), updated_at = now()
WHERE id = @id AND state = 'running' AND (backup_started_at IS NULL OR backup_started_at < @stale_before)
RETURNING *;

-- name: AnyDBServerBackup :one
-- Whether a base backup exists to restore from: every generation backs up
-- to the same storage prefix, so any generation's backup will do.
SELECT EXISTS (SELECT 1 FROM app_db_servers WHERE last_backup_at IS NOT NULL)::boolean;

-- name: DBServerBackupFinished :exec
UPDATE app_db_servers
SET backup_started_at = NULL,
    last_backup_at = CASE WHEN @ok::boolean THEN now() ELSE last_backup_at END,
    last_backup_name = CASE WHEN @ok::boolean THEN @backup_name::text ELSE last_backup_name END,
    last_backup_error = @backup_error, updated_at = now()
WHERE id = @id;

-- name: SetDBServerTLS :exec
UPDATE app_db_servers SET tls_expires_at = @tls_expires_at, updated_at = now() WHERE id = @id;

-- name: SetDBServerError :exec
UPDATE app_db_servers SET last_error = @last_error, updated_at = now() WHERE id = @id;

-- name: LockDatabaseNodes :many
-- Nodes that may host the app database server, locked in the same order
-- as app placement.
SELECT id, name, memory_total_bytes, cpu_count, disk_free_bytes, disk_total_bytes, labels,
       db_address, db_publish_address, db_port
FROM nodes
WHERE status = 'ready' AND NOT draining AND removed_at IS NULL
  AND db_address <> '' AND db_port > 0 AND db_unavailable_reason = ''
ORDER BY id
FOR UPDATE;

-- name: GetNodeDBInfo :one
SELECT id, name, status, draining, db_address, db_publish_address, db_port, db_unavailable_reason
FROM nodes WHERE id = @id;

-- App databases.

-- name: CreateAppDatabase :one
INSERT INTO app_databases (app_id, workspace_id, name, password, password_key_version, connection_limit, created_by)
VALUES (@app_id, @workspace_id, @name, @password, @password_key_version, @connection_limit, @created_by)
RETURNING *;

-- name: GetAppDatabase :one
SELECT * FROM app_databases WHERE app_id = @app_id;

-- name: LockAppDatabase :one
SELECT * FROM app_databases WHERE app_id = @app_id FOR UPDATE;

-- name: CountWorkspaceDatabases :one
SELECT count(*)::bigint FROM app_databases WHERE workspace_id = @workspace_id;

-- name: CountAppDatabases :one
SELECT count(*)::bigint FROM app_databases;

-- name: ListAppDatabasesToProvision :many
SELECT * FROM app_databases d
WHERE d.state = 'creating' AND EXISTS (SELECT 1 FROM apps a WHERE a.id = d.app_id AND a.deleted_at IS NULL)
ORDER BY d.created_at
LIMIT @row_limit;

-- name: ListAppDatabasesToDrop :many
-- Databases to drop: asked for, or their app was deleted.
SELECT * FROM app_databases d
WHERE d.state = 'deleting' OR EXISTS (SELECT 1 FROM apps a WHERE a.id = d.app_id AND a.deleted_at IS NOT NULL)
ORDER BY d.created_at
LIMIT @row_limit;

-- name: ListAppDatabases :many
-- Every database with its app (for re-pointing apps after a failover and
-- for monitoring).
SELECT sqlc.embed(d), a.slug AS app_slug, a.current_deployment_id
FROM app_databases d JOIN apps a ON a.id = d.app_id
WHERE a.deleted_at IS NULL
ORDER BY d.created_at;

-- name: AppDatabaseReady :one
UPDATE app_databases
SET state = 'ready', ready_at = now(), last_error = '', server_generation = @server_generation, updated_at = now()
WHERE app_id = @app_id AND state = 'creating'
RETURNING *;

-- name: SetAppDatabaseGeneration :exec
UPDATE app_databases SET server_generation = @server_generation, updated_at = now()
WHERE app_id = @app_id AND state = 'ready';

-- name: SetAppDatabaseError :exec
UPDATE app_databases SET last_error = @last_error, updated_at = now() WHERE app_id = @app_id;

-- name: MarkAppDatabaseDeleting :one
UPDATE app_databases SET state = 'deleting', updated_at = now()
WHERE app_id = @app_id AND state <> 'deleting'
RETURNING *;

-- name: DeleteAppDatabase :exec
DELETE FROM app_databases WHERE app_id = @app_id;

-- name: SetAppDatabasePassword :exec
UPDATE app_databases
SET password = @password, password_key_version = @password_key_version, password_rotated_at = now(), updated_at = now()
WHERE app_id = @app_id;

-- name: SetAppDatabaseStats :exec
UPDATE app_databases SET size_bytes = @size_bytes, connections = @connections WHERE name = @name;

-- name: ListAppDatabasesNotOnVersion :many
-- Passwords sealed with another master key version (rotation).
SELECT app_id, password, password_key_version FROM app_databases
WHERE password_key_version <> @version ORDER BY app_id LIMIT @row_limit;

-- name: ReencryptAppDatabasePassword :execrows
UPDATE app_databases SET password = @password, password_key_version = @new_version
WHERE app_id = @app_id AND password_key_version = @old_version;

-- name: ListDBServersNotOnVersion :many
SELECT id, superuser_password, password_key_version FROM app_db_servers
WHERE password_key_version <> @version ORDER BY id LIMIT @row_limit;

-- name: ReencryptDBServerPassword :execrows
UPDATE app_db_servers SET superuser_password = @superuser_password, password_key_version = @new_version
WHERE id = @id AND password_key_version = @old_version;

-- Dumps.

-- name: CreateDBDump :one
INSERT INTO app_db_dumps (app_id, workspace_id, object_key, created_by, expires_at)
VALUES (@app_id, @workspace_id, @object_key, @created_by, @expires_at)
RETURNING *;

-- name: GetDBDump :one
SELECT * FROM app_db_dumps WHERE id = @id AND app_id = @app_id;

-- name: GetDBDumpByID :one
SELECT * FROM app_db_dumps WHERE id = @id;

-- name: DBDumpDumped :one
UPDATE app_db_dumps SET state = 'uploading', size_bytes = @size_bytes, sha256 = @sha256
WHERE id = @id AND state = 'dumping'
RETURNING *;

-- name: DBDumpReady :one
UPDATE app_db_dumps SET state = 'ready', finished_at = now(), expires_at = @expires_at
WHERE id = @id AND state = 'uploading'
RETURNING *;

-- name: DBDumpFailed :exec
UPDATE app_db_dumps SET state = 'failed', error = @error, finished_at = now()
WHERE id = @id AND state IN ('dumping', 'uploading');

-- name: FailStaleDBDumps :exec
UPDATE app_db_dumps SET state = 'failed', error = 'the dump did not finish in time', finished_at = now()
WHERE state IN ('dumping', 'uploading') AND created_at < @before;

-- name: ListExpiredDBDumps :many
SELECT * FROM app_db_dumps WHERE expires_at < now() ORDER BY expires_at LIMIT @row_limit;

-- name: DeleteDBDump :exec
DELETE FROM app_db_dumps WHERE id = @id;
