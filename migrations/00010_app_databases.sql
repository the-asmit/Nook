-- App databases: one PostgreSQL server per installation (a "generation"
-- of it at a time; a failover restores the next generation on another
-- node), one database and role per app, encrypted WAL-G backups, dumps.

-- +goose Up
CREATE TYPE app_db_server_state AS ENUM (
    'starting',  -- the agent was asked to start (or restore) it
    'running',   -- accepting connections, not recovering
    'stopping',  -- a planned failover: clean shutdown and final archive
    'fenced',    -- replaced; its container must not run (volume kept)
    'removed',   -- an admin removed its container and volume
    'failed'     -- could not start; the next generation replaces it
);

CREATE TABLE app_db_servers (
    id                   uuid PRIMARY KEY DEFAULT uuidv7(),
    generation           integer NOT NULL,
    state                app_db_server_state NOT NULL DEFAULT 'starting',
    -- How its data directory comes to be: init (empty, the first server),
    -- restore (from the backups of earlier generations).
    mode                 text NOT NULL,
    -- Why this generation exists: first, failover (its node died),
    -- planned (an admin moved it), retry (the previous one failed).
    cause                text NOT NULL,
    cause_at             timestamptz NOT NULL DEFAULT now(),
    node_id              uuid REFERENCES nodes (id) ON DELETE SET NULL,
    node_name            text NOT NULL,
    -- Where apps connect, as the agent reported it once running.
    address              text NOT NULL DEFAULT '',
    port                 integer NOT NULL DEFAULT 0,
    memory_mb            integer NOT NULL,
    -- The control plane's superuser password, sealed with the keyring.
    superuser_password   bytea NOT NULL,
    password_key_version integer NOT NULL,
    -- The master key version the backup encryption key is derived from;
    -- every generation of one installation uses the same one.
    backup_key_version   integer NOT NULL,
    start_sent_at        timestamptz,
    running_at           timestamptz,
    tls_expires_at       timestamptz,
    last_error           text NOT NULL DEFAULT '',
    -- What the leader's monitor pass last saw (pg_stat_archiver, sizes).
    checked_at           timestamptz,
    archived_count       bigint NOT NULL DEFAULT 0,
    last_archived_wal    text NOT NULL DEFAULT '',
    last_archived_at     timestamptz,
    archive_failed_count bigint NOT NULL DEFAULT 0,
    last_failed_wal      text NOT NULL DEFAULT '',
    last_failed_at       timestamptz,
    databases_size_bytes bigint NOT NULL DEFAULT 0,
    connections          integer NOT NULL DEFAULT 0,
    -- Base backups.
    backup_started_at    timestamptz,
    last_backup_at       timestamptz,
    last_backup_name     text NOT NULL DEFAULT '',
    last_backup_error    text NOT NULL DEFAULT '',
    -- A planned failover's target, and the last WAL segment the stopped
    -- server archived.
    move_to_node_id      uuid REFERENCES nodes (id) ON DELETE SET NULL,
    stop_requested_at    timestamptz,
    stop_sent_at         timestamptz,
    final_wal            text NOT NULL DEFAULT '',
    stopped_at           timestamptz,
    fenced_at            timestamptz,
    removed_at           timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT app_db_servers_generation_positive CHECK (generation > 0),
    CONSTRAINT app_db_servers_mode_values CHECK (mode IN ('init', 'restore')),
    CONSTRAINT app_db_servers_cause_values CHECK (cause IN ('first', 'failover', 'planned', 'retry')),
    CONSTRAINT app_db_servers_port_range CHECK (port BETWEEN 0 AND 65535),
    CONSTRAINT app_db_servers_memory_positive CHECK (memory_mb > 0),
    CONSTRAINT app_db_servers_error_length CHECK (char_length(last_error) <= 1000 AND char_length(last_backup_error) <= 1000)
);
CREATE UNIQUE INDEX app_db_servers_generation_unique ON app_db_servers (generation);
-- At most one server is current: the one apps use or will use.
CREATE UNIQUE INDEX app_db_servers_one_current ON app_db_servers ((true))
    WHERE state IN ('starting', 'running', 'stopping');
CREATE INDEX app_db_servers_node ON app_db_servers (node_id) WHERE node_id IS NOT NULL;

CREATE TYPE app_database_state AS ENUM ('creating', 'ready', 'deleting');

CREATE TABLE app_databases (
    -- RESTRICT: a deleted app is purged only after its database is dropped.
    app_id               uuid PRIMARY KEY REFERENCES apps (id) ON DELETE RESTRICT,
    workspace_id         uuid NOT NULL REFERENCES workspaces (id) ON DELETE RESTRICT,
    -- The database's and the role's name.
    name                 text NOT NULL,
    state                app_database_state NOT NULL DEFAULT 'creating',
    -- The role's password, sealed with the keyring.
    password             bytea NOT NULL,
    password_key_version integer NOT NULL,
    connection_limit     integer NOT NULL,
    -- The server generation whose address the app's DATABASE_URL holds
    -- (NULL: not set yet); a failover re-points apps on older ones.
    server_generation    integer,
    -- What the monitor pass last measured.
    size_bytes           bigint NOT NULL DEFAULT 0,
    connections          integer NOT NULL DEFAULT 0,
    last_error           text NOT NULL DEFAULT '',
    created_by           uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    ready_at             timestamptz,
    password_rotated_at  timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT app_databases_name_format CHECK (name ~ '^app_[0-9a-f]{32}$'),
    CONSTRAINT app_databases_connection_limit_range CHECK (connection_limit BETWEEN 1 AND 10000),
    CONSTRAINT app_databases_error_length CHECK (char_length(last_error) <= 1000)
);
CREATE UNIQUE INDEX app_databases_name_unique ON app_databases (name);
CREATE INDEX app_databases_workspace ON app_databases (workspace_id);

CREATE TABLE app_db_dumps (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    app_id       uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    -- dumping (pg_dump runs on the database node), uploading, ready, failed.
    state        text NOT NULL DEFAULT 'dumping',
    object_key   text NOT NULL,
    size_bytes   bigint NOT NULL DEFAULT 0,
    sha256       bytea,
    error        text NOT NULL DEFAULT '',
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    -- The object is deleted after this time.
    expires_at   timestamptz NOT NULL,
    CONSTRAINT app_db_dumps_state_values CHECK (state IN ('dumping', 'uploading', 'ready', 'failed')),
    CONSTRAINT app_db_dumps_error_length CHECK (char_length(error) <= 1000)
);
CREATE INDEX app_db_dumps_expires ON app_db_dumps (expires_at);

-- What a node's agent offers for the app database server: the address
-- apps reach it at, the port it publishes, and why it cannot host one.
ALTER TABLE nodes
    ADD COLUMN db_address text NOT NULL DEFAULT '',
    ADD COLUMN db_publish_address text NOT NULL DEFAULT '',
    ADD COLUMN db_port integer NOT NULL DEFAULT 0,
    ADD COLUMN db_unavailable_reason text NOT NULL DEFAULT '',
    ADD CONSTRAINT nodes_db_port_range CHECK (db_port BETWEEN 0 AND 65535),
    ADD CONSTRAINT nodes_db_unavailable_reason_length CHECK (char_length(db_unavailable_reason) <= 500);

ALTER TABLE workspace_quotas ADD COLUMN max_databases integer NOT NULL DEFAULT 5;
ALTER TABLE workspace_quotas ALTER COLUMN max_databases DROP DEFAULT;
ALTER TABLE workspace_quotas ADD CONSTRAINT workspace_quotas_max_databases_range CHECK (max_databases BETWEEN 0 AND 1000);

-- +goose Down
ALTER TABLE workspace_quotas DROP COLUMN max_databases;
ALTER TABLE nodes
    DROP COLUMN db_unavailable_reason,
    DROP COLUMN db_port,
    DROP COLUMN db_publish_address,
    DROP COLUMN db_address;
DROP TABLE app_db_dumps;
DROP TABLE app_databases;
DROP TYPE app_database_state;
DROP TABLE app_db_servers;
DROP TYPE app_db_server_state;
