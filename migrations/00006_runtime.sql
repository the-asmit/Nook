-- Running apps: where each app runs (instances on nodes), what it should
-- be doing (desired state, current deployment), its environment variables
-- (encrypted) and the immutable environment snapshot of every deployment.

-- +goose Up
CREATE TYPE app_desired_state AS ENUM ('running', 'stopped');
-- How a deployment came to be: built from uploaded source, or a new
-- release of an existing image (environment change, rollback).
CREATE TYPE deployment_kind AS ENUM ('build', 'config', 'rollback');
CREATE TYPE instance_state AS ENUM (
    'starting', 'healthy', 'unhealthy', 'stopping', 'stopped', 'crashed', 'failed'
);

-- Environment values are AES-256-GCM ciphertexts (nonce || sealed value)
-- bound to the app and key; the database never holds plaintext.
CREATE TABLE env_snapshots (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    app_id     uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX env_snapshots_app_idx ON env_snapshots (app_id);

CREATE TABLE env_snapshot_vars (
    snapshot_id uuid NOT NULL REFERENCES env_snapshots (id) ON DELETE CASCADE,
    key         text NOT NULL,
    value       bytea NOT NULL,
    key_version integer NOT NULL,
    is_secret   boolean NOT NULL,
    PRIMARY KEY (snapshot_id, key)
);

CREATE TABLE app_env (
    app_id      uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    key         text NOT NULL,
    value       bytea NOT NULL,
    key_version integer NOT NULL,
    is_secret   boolean NOT NULL DEFAULT false,
    updated_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, key),
    CONSTRAINT app_env_key_format CHECK (key ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
    -- 32 KiB of value plus nonce and tag.
    CONSTRAINT app_env_value_size CHECK (octet_length(value) BETWEEN 28 AND 32796),
    CONSTRAINT app_env_key_version_positive CHECK (key_version >= 1)
);

-- One row per master-key version ever used: a value encrypted with that
-- key, so a server started with a different key for the same version
-- fails at startup instead of failing to decrypt later.
CREATE TABLE secret_key_checks (
    version    integer PRIMARY KEY,
    check_value bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT secret_key_checks_version_positive CHECK (version >= 1)
);

ALTER TABLE deployments
    ADD COLUMN kind deployment_kind NOT NULL DEFAULT 'build',
    -- For config and rollback deployments: the deployment whose image
    -- they release again.
    ADD COLUMN image_of_deployment_id uuid REFERENCES deployments (id) ON DELETE SET NULL,
    ADD COLUMN rollback_to integer,
    ADD COLUMN env_snapshot_id uuid REFERENCES env_snapshots (id) ON DELETE SET NULL,
    ADD COLUMN deploying_at timestamptz,
    ADD COLUMN live_at timestamptz,
    ADD COLUMN superseded_at timestamptz,
    ADD COLUMN rolled_back_at timestamptz,
    ADD CONSTRAINT deployments_released_has_digest
        CHECK (status NOT IN ('deploying', 'live', 'superseded', 'rolled_back') OR image_digest IS NOT NULL);
-- At most one rollout and one live deployment per app, enforced by the
-- database rather than by the rollout owner's good behaviour.
CREATE UNIQUE INDEX deployments_one_deploying_per_app ON deployments (app_id) WHERE status = 'deploying';
CREATE UNIQUE INDEX deployments_one_live_per_app ON deployments (app_id) WHERE status = 'live';

ALTER TABLE apps
    ADD COLUMN desired_state app_desired_state NOT NULL DEFAULT 'running',
    -- When the desired state was last set: `nook apps start` after a crash
    -- loop asks for a fresh instance even though the app was "running".
    ADD COLUMN desired_state_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN current_deployment_id uuid REFERENCES deployments (id) ON DELETE SET NULL,
    ADD COLUMN startup_timeout_seconds integer NOT NULL DEFAULT 60,
    ADD COLUMN read_only_rootfs boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT apps_startup_timeout_range CHECK (startup_timeout_seconds BETWEEN 1 AND 3600);

CREATE TABLE app_instances (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    app_id            uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    deployment_id     uuid NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    workspace_id      uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    node_id           uuid REFERENCES nodes (id) ON DELETE SET NULL,
    node_name         text NOT NULL,
    state             instance_state NOT NULL DEFAULT 'starting',
    -- The reservation on the node: the app's limits when it was placed.
    memory_mb         integer NOT NULL,
    cpu_millicores    integer NOT NULL,
    container_id      text,
    -- Where the node publishes the app: its private advertise address.
    address           text NOT NULL DEFAULT '',
    host_port         integer,
    restart_count     integer NOT NULL DEFAULT 0,
    start_sent_at     timestamptz,
    started_at        timestamptz,
    last_healthy_at   timestamptz,
    stop_requested_at timestamptz,
    stopped_at        timestamptz,
    -- Shown to users; never contains internal details or secrets.
    last_error        text NOT NULL DEFAULT '',
    -- The container's output when it failed to start, kept for the user.
    startup_log       text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT app_instances_limits_positive CHECK (memory_mb > 0 AND cpu_millicores > 0),
    CONSTRAINT app_instances_host_port_range CHECK (host_port BETWEEN 1 AND 65535),
    CONSTRAINT app_instances_restart_count_non_negative CHECK (restart_count >= 0),
    CONSTRAINT app_instances_last_error_length CHECK (char_length(last_error) <= 500),
    CONSTRAINT app_instances_startup_log_length CHECK (octet_length(startup_log) <= 65536)
);
-- Instances holding a reservation on their node.
CREATE INDEX app_instances_node_reserved_idx ON app_instances (node_id)
    WHERE state IN ('starting', 'healthy', 'unhealthy', 'stopping');
CREATE INDEX app_instances_app_idx ON app_instances (app_id, created_at DESC);
CREATE INDEX app_instances_workspace_reserved_idx ON app_instances (workspace_id)
    WHERE state IN ('starting', 'healthy', 'unhealthy', 'stopping');
-- A deployment runs as one instance at a time (no replicas yet).
CREATE UNIQUE INDEX app_instances_one_running_per_deployment ON app_instances (deployment_id)
    WHERE state IN ('starting', 'healthy', 'unhealthy');

-- Existing overrides get the default memory quota of new installations.
ALTER TABLE workspace_quotas ADD COLUMN max_memory_mb integer NOT NULL DEFAULT 8192;
ALTER TABLE workspace_quotas ALTER COLUMN max_memory_mb DROP DEFAULT;
ALTER TABLE workspace_quotas ADD CONSTRAINT workspace_quotas_max_memory_range CHECK (max_memory_mb BETWEEN 0 AND 10485760);

-- The private address apps on the node are published on, and why the
-- node cannot build (empty when it can).
ALTER TABLE nodes ADD COLUMN advertise_address text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN builds_unavailable_reason text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD CONSTRAINT nodes_builds_unavailable_reason_length CHECK (char_length(builds_unavailable_reason) <= 500);

-- +goose Down
ALTER TABLE nodes DROP COLUMN builds_unavailable_reason;
ALTER TABLE nodes DROP COLUMN advertise_address;
ALTER TABLE workspace_quotas DROP COLUMN max_memory_mb;
DROP TABLE app_instances;
ALTER TABLE apps
    DROP COLUMN read_only_rootfs,
    DROP COLUMN startup_timeout_seconds,
    DROP COLUMN current_deployment_id,
    DROP COLUMN desired_state_at,
    DROP COLUMN desired_state;
DROP INDEX deployments_one_live_per_app;
DROP INDEX deployments_one_deploying_per_app;
-- Released deployments fall back to the last status 00004 knows.
UPDATE deployments SET status = 'built' WHERE status IN ('deploying', 'live', 'superseded', 'rolled_back');
ALTER TABLE deployments
    DROP CONSTRAINT deployments_released_has_digest,
    DROP COLUMN rolled_back_at,
    DROP COLUMN superseded_at,
    DROP COLUMN live_at,
    DROP COLUMN deploying_at,
    DROP COLUMN env_snapshot_id,
    DROP COLUMN rollback_to,
    DROP COLUMN image_of_deployment_id,
    DROP COLUMN kind;
DROP TABLE secret_key_checks;
DROP TABLE app_env;
DROP TABLE env_snapshot_vars;
DROP TABLE env_snapshots;
DROP TYPE instance_state;
DROP TYPE deployment_kind;
DROP TYPE app_desired_state;
