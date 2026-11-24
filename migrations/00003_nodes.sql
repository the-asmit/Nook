-- Worker nodes: join tokens, nodes, their client certificates and the
-- append-only log of node state transitions.

-- +goose Up
CREATE TYPE node_status AS ENUM ('joining', 'ready', 'suspect', 'dead', 'draining', 'removed');

CREATE TABLE join_tokens (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    -- SHA-256 of the nook_join_... token; the token itself is shown once.
    token_hash   bytea NOT NULL,
    prefix       text NOT NULL,
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    max_uses     integer NOT NULL DEFAULT 1,
    uses         integer NOT NULL DEFAULT 0,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    CONSTRAINT join_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT join_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT join_tokens_max_uses_range CHECK (max_uses BETWEEN 1 AND 1000),
    CONSTRAINT join_tokens_uses_range CHECK (uses BETWEEN 0 AND max_uses),
    CONSTRAINT join_tokens_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE TABLE nodes (
    id                     uuid PRIMARY KEY DEFAULT uuidv7(),
    name                   text NOT NULL,
    -- Combined lifecycle and health state; see docs/decisions/0015.
    status                 node_status NOT NULL DEFAULT 'joining',
    -- Admin intent, kept separately so that a draining node that goes
    -- dead and comes back returns to "draining", not "ready".
    draining               boolean NOT NULL DEFAULT false,
    labels                 jsonb NOT NULL DEFAULT '{}',
    hostname               text NOT NULL DEFAULT '',
    addresses              text[] NOT NULL DEFAULT '{}',
    cpu_count              integer NOT NULL DEFAULT 0,
    memory_total_bytes     bigint NOT NULL DEFAULT 0,
    disk_total_bytes       bigint NOT NULL DEFAULT 0,
    docker_version         text NOT NULL DEFAULT '',
    agent_version          text NOT NULL DEFAULT '',
    os                     text NOT NULL DEFAULT '',
    arch                   text NOT NULL DEFAULT '',
    joined_with_token_id   uuid REFERENCES join_tokens (id) ON DELETE SET NULL,
    joined_at              timestamptz NOT NULL DEFAULT now(),
    -- Latest heartbeat persisted from Redis (throttled), timestamped with
    -- the control plane's clock on receipt.
    last_heartbeat_at      timestamptz,
    memory_available_bytes bigint,
    cpu_load_1m            double precision,
    disk_free_bytes        bigint,
    running_containers     integer,
    docker_reachable       boolean,
    removed_at             timestamptz,
    CONSTRAINT nodes_name_format CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT nodes_labels_object CHECK (jsonb_typeof(labels) = 'object'),
    CONSTRAINT nodes_removed_consistent CHECK ((status = 'removed') = (removed_at IS NOT NULL)),
    CONSTRAINT nodes_resources_non_negative CHECK (cpu_count >= 0 AND memory_total_bytes >= 0 AND disk_total_bytes >= 0)
);
-- Names identify live nodes; a removed node's name can be reused.
CREATE UNIQUE INDEX nodes_name_active_key ON nodes (name) WHERE removed_at IS NULL;

CREATE TABLE node_certificates (
    -- Hex-encoded certificate serial number.
    serial     text PRIMARY KEY,
    node_id    uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    not_before timestamptz NOT NULL,
    not_after  timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT node_certificates_serial_format CHECK (serial ~ '^[0-9a-f]{1,40}$'),
    CONSTRAINT node_certificates_validity CHECK (not_after > not_before)
);
CREATE INDEX node_certificates_node_id_idx ON node_certificates (node_id);

CREATE TABLE node_events (
    id          uuid PRIMARY KEY DEFAULT uuidv7(),
    -- No foreign key: the history outlives the node row.
    node_id     uuid NOT NULL,
    from_status node_status,
    to_status   node_status NOT NULL,
    reason      text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT node_events_reason_length CHECK (char_length(reason) <= 200)
);
CREATE INDEX node_events_node_idx ON node_events (node_id, id);

-- +goose StatementBegin
CREATE FUNCTION reject_append_only_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only (% rejected)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER node_events_no_update_delete BEFORE UPDATE OR DELETE ON node_events
    FOR EACH ROW EXECUTE FUNCTION reject_append_only_change();
CREATE TRIGGER node_events_no_truncate BEFORE TRUNCATE ON node_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_append_only_change();

-- +goose Down
DROP TABLE node_events;
DROP FUNCTION reject_append_only_change();
DROP TABLE node_certificates;
DROP TABLE nodes;
DROP TABLE join_tokens;
DROP TYPE node_status;
