-- Apps, their deployments and the builds that turn uploaded source into
-- images, plus per-workspace quotas and the build capacity of nodes.

-- +goose Up
CREATE TYPE deployment_status AS ENUM (
    'pending', 'uploading', 'queued', 'building', 'built', 'failed', 'cancelled'
);
-- How one build attempt ended. succeeded/failed/timed_out/cancelled are
-- final for the deployment; infra_error and lost are retried elsewhere.
CREATE TYPE build_result AS ENUM (
    'succeeded', 'failed', 'timed_out', 'cancelled', 'infra_error', 'lost'
);

-- Overrides of the instance-wide default quotas, set by instance admins.
CREATE TABLE workspace_quotas (
    workspace_id          uuid PRIMARY KEY REFERENCES workspaces (id) ON DELETE CASCADE,
    max_apps              integer NOT NULL,
    max_concurrent_builds integer NOT NULL,
    updated_by            uuid REFERENCES users (id) ON DELETE SET NULL,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspace_quotas_max_apps_range CHECK (max_apps BETWEEN 0 AND 10000),
    CONSTRAINT workspace_quotas_max_builds_range CHECK (max_concurrent_builds BETWEEN 0 AND 100)
);

CREATE TABLE apps (
    id                     uuid PRIMARY KEY DEFAULT uuidv7(),
    -- RESTRICT: a workspace can only be deleted once its apps (and their
    -- images, sources and logs) have been purged.
    workspace_id           uuid NOT NULL REFERENCES workspaces (id) ON DELETE RESTRICT,
    slug                   text NOT NULL,
    name                   text NOT NULL,
    created_by             uuid REFERENCES users (id) ON DELETE SET NULL,
    port                   integer NOT NULL DEFAULT 8080,
    health_check_path      text NOT NULL DEFAULT '/',
    memory_mb              integer NOT NULL DEFAULT 256,
    cpu_millicores         integer NOT NULL DEFAULT 500,
    -- Deployment numbers are handed out by incrementing this under the
    -- app row's lock, so concurrent deploys never share a number.
    next_deployment_number integer NOT NULL DEFAULT 1,
    created_at             timestamptz NOT NULL DEFAULT now(),
    deleted_at             timestamptz,
    CONSTRAINT apps_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$'),
    CONSTRAINT apps_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT apps_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT apps_health_check_path_format CHECK (health_check_path ~ '^/[\x21-\x7e]{0,199}$'),
    CONSTRAINT apps_memory_range CHECK (memory_mb BETWEEN 16 AND 1048576),
    CONSTRAINT apps_cpu_range CHECK (cpu_millicores BETWEEN 10 AND 1024000),
    CONSTRAINT apps_next_number_positive CHECK (next_deployment_number >= 1)
);
-- Slugs name live apps; a deleted app's slug can be reused.
CREATE UNIQUE INDEX apps_workspace_slug_active_key ON apps (workspace_id, slug) WHERE deleted_at IS NULL;

CREATE TABLE deployments (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    app_id              uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    number              integer NOT NULL,
    status              deployment_status NOT NULL DEFAULT 'pending',
    -- Unguessable object key of the uploaded source archive.
    source_key          text NOT NULL,
    source_sha256       bytea NOT NULL,
    source_size         bigint NOT NULL,
    upload_expires_at   timestamptz NOT NULL,
    image_digest        text,
    created_by          uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Shown to users; never contains internal details.
    failure_reason      text NOT NULL DEFAULT '',
    cancel_requested_at timestamptz,
    -- Last time a job for this deployment was added to the build queue.
    enqueued_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    uploading_at        timestamptz,
    queued_at           timestamptz,
    building_at         timestamptz,
    built_at            timestamptz,
    failed_at           timestamptz,
    cancelled_at        timestamptz,
    source_deleted_at   timestamptz,
    image_deleted_at    timestamptz,
    CONSTRAINT deployments_app_number_key UNIQUE (app_id, number),
    CONSTRAINT deployments_number_positive CHECK (number >= 1),
    CONSTRAINT deployments_source_sha256_length CHECK (octet_length(source_sha256) = 32),
    CONSTRAINT deployments_source_size_positive CHECK (source_size > 0),
    CONSTRAINT deployments_image_digest_format CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT deployments_built_has_digest CHECK (status <> 'built' OR image_digest IS NOT NULL),
    CONSTRAINT deployments_failure_reason_length CHECK (char_length(failure_reason) <= 500)
);
CREATE INDEX deployments_active_idx ON deployments (status, created_at)
    WHERE status IN ('pending', 'uploading', 'queued', 'building');
CREATE INDEX deployments_app_built_idx ON deployments (app_id, number DESC) WHERE status = 'built';

CREATE TABLE builds (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    deployment_id  uuid NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    app_id         uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    workspace_id   uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    node_id        uuid REFERENCES nodes (id) ON DELETE SET NULL,
    node_name      text NOT NULL,
    attempt        integer NOT NULL,
    -- Registry tag the build pushes; unique per build so a stray push from
    -- an abandoned attempt can never overwrite the recorded image.
    image_tag      text NOT NULL,
    dispatched_at  timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    finished_at    timestamptz,
    result         build_result,
    message        text NOT NULL DEFAULT '',
    image_digest   text,
    log_key        text,
    log_bytes      bigint,
    cancel_sent_at timestamptz,
    CONSTRAINT builds_deployment_attempt_key UNIQUE (deployment_id, attempt),
    CONSTRAINT builds_attempt_positive CHECK (attempt >= 1),
    CONSTRAINT builds_finished_has_result CHECK ((finished_at IS NULL) = (result IS NULL)),
    CONSTRAINT builds_image_digest_format CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT builds_message_length CHECK (char_length(message) <= 500)
);
-- Idempotency and the "one active build per app" rule, enforced by the
-- database rather than by the dispatcher's good behaviour.
CREATE UNIQUE INDEX builds_one_active_per_deployment ON builds (deployment_id) WHERE finished_at IS NULL;
CREATE UNIQUE INDEX builds_one_active_per_app ON builds (app_id) WHERE finished_at IS NULL;
CREATE INDEX builds_active_node_idx ON builds (node_id) WHERE finished_at IS NULL;
CREATE INDEX builds_active_workspace_idx ON builds (workspace_id) WHERE finished_at IS NULL;

-- How many builds a node's agent runs at once (0 = it does not build).
ALTER TABLE nodes ADD COLUMN build_slots integer NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD CONSTRAINT nodes_build_slots_range CHECK (build_slots BETWEEN 0 AND 64);

-- +goose Down
ALTER TABLE nodes DROP COLUMN build_slots;
DROP TABLE builds;
DROP TABLE deployments;
DROP TABLE apps;
DROP TABLE workspace_quotas;
DROP TYPE build_result;
DROP TYPE deployment_status;
