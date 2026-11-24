-- Identity and access: users, workspaces, memberships, invitations,
-- browser sessions, API tokens, CLI device authorizations and the audit log.
--
-- IDs are UUIDv7 (time-ordered, so B-tree inserts stay local and IDs sort
-- by creation time); uuidv7() is built into PostgreSQL 18.
-- Secrets (session tokens, API tokens, device codes) are never stored, only
-- their SHA-256 digests.

-- +goose Up
CREATE TYPE workspace_role AS ENUM ('owner', 'admin', 'member');
CREATE TYPE device_status AS ENUM ('pending', 'approved', 'denied', 'expired', 'consumed');

CREATE TABLE users (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    email             citext NOT NULL,
    name              text NOT NULL DEFAULT '',
    avatar_url        text NOT NULL DEFAULT '',
    -- Identity is the (issuer, subject) pair from the OIDC provider; the
    -- email is contact data that can change. See ADR 0008.
    oidc_issuer       text NOT NULL,
    oidc_subject      text NOT NULL,
    is_instance_admin boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_login_at     timestamptz,
    disabled_at       timestamptz,
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_oidc_identity_key UNIQUE (oidc_issuer, oidc_subject),
    CONSTRAINT users_email_format CHECK (char_length(email) BETWEEN 3 AND 254 AND email LIKE '%_@_%'),
    CONSTRAINT users_name_length CHECK (char_length(name) <= 200),
    CONSTRAINT users_avatar_url_length CHECK (char_length(avatar_url) <= 2048),
    CONSTRAINT users_oidc_issuer_length CHECK (char_length(oidc_issuer) BETWEEN 1 AND 2048),
    CONSTRAINT users_oidc_subject_length CHECK (char_length(oidc_subject) BETWEEN 1 AND 255)
);

CREATE TABLE workspaces (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    name              text NOT NULL,
    slug              text NOT NULL,
    -- Set for the workspace created automatically for a user at first
    -- sign-in; at most one per user.
    personal_owner_id uuid REFERENCES users (id) ON DELETE CASCADE,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workspaces_slug_key UNIQUE (slug),
    CONSTRAINT workspaces_personal_owner_key UNIQUE (personal_owner_id),
    CONSTRAINT workspaces_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT workspaces_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$')
);

CREATE TABLE memberships (
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role         workspace_role NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);
-- "Which workspaces is this user in?" is asked on almost every request.
CREATE INDEX memberships_user_id_idx ON memberships (user_id);

CREATE TABLE invitations (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    workspace_id uuid NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    email        citext NOT NULL,
    role         workspace_role NOT NULL,
    invited_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz,
    CONSTRAINT invitations_email_format CHECK (char_length(email) BETWEEN 3 AND 254 AND email LIKE '%_@_%'),
    CONSTRAINT invitations_expiry_after_creation CHECK (expires_at > created_at)
);
-- At most one open invitation per (workspace, email).
CREATE UNIQUE INDEX invitations_open_key ON invitations (workspace_id, email) WHERE accepted_at IS NULL;
-- Sign-in looks up open invitations by email.
CREATE INDEX invitations_open_email_idx ON invitations (email) WHERE accepted_at IS NULL;

CREATE TABLE sessions (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id             uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash          bytea NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    user_agent          text NOT NULL DEFAULT '',
    ip                  inet,
    revoked_at          timestamptz,
    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
    CONSTRAINT sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sessions_user_agent_length CHECK (char_length(user_agent) <= 512),
    CONSTRAINT sessions_idle_within_absolute CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   bytea NOT NULL,
    prefix       text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    CONSTRAINT api_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT api_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT api_tokens_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT api_tokens_prefix_length CHECK (char_length(prefix) BETWEEN 1 AND 32)
);
CREATE INDEX api_tokens_user_id_idx ON api_tokens (user_id, id);

CREATE TABLE device_authorizations (
    id                    uuid PRIMARY KEY DEFAULT uuidv7(),
    device_code_hash      bytea NOT NULL,
    -- Normalized (upper-case, no separator) code the user types.
    user_code             text NOT NULL,
    status                device_status NOT NULL DEFAULT 'pending',
    user_id               uuid REFERENCES users (id) ON DELETE CASCADE,
    client_name           text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    last_polled_at        timestamptz,
    poll_interval_seconds integer NOT NULL,
    api_token_id          uuid REFERENCES api_tokens (id) ON DELETE SET NULL,
    CONSTRAINT device_authorizations_code_hash_key UNIQUE (device_code_hash),
    CONSTRAINT device_authorizations_code_hash_length CHECK (octet_length(device_code_hash) = 32),
    CONSTRAINT device_authorizations_user_code_format CHECK (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{8}$'),
    CONSTRAINT device_authorizations_client_name_length CHECK (char_length(client_name) BETWEEN 1 AND 100),
    CONSTRAINT device_authorizations_interval_range CHECK (poll_interval_seconds BETWEEN 1 AND 300),
    CONSTRAINT device_authorizations_decided_by_user CHECK (status IN ('pending', 'expired') OR user_id IS NOT NULL)
);
-- A user code identifies at most one live request; expired or finished
-- requests release their code for reuse.
CREATE UNIQUE INDEX device_authorizations_pending_user_code_key ON device_authorizations (user_code) WHERE status = 'pending';

CREATE TABLE audit_log (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    -- No foreign keys: audit records must outlive the users and workspaces
    -- they describe.
    workspace_id  uuid,
    actor_user_id uuid,
    action        text NOT NULL,
    target_type   text NOT NULL DEFAULT '',
    target_id     text NOT NULL DEFAULT '',
    metadata      jsonb NOT NULL DEFAULT '{}',
    ip            inet,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_log_action_format CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
    CONSTRAINT audit_log_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX audit_log_workspace_idx ON audit_log (workspace_id, id DESC) WHERE workspace_id IS NOT NULL;
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, id DESC) WHERE actor_user_id IS NOT NULL;

-- The audit log is append-only: reject UPDATE, DELETE and TRUNCATE even
-- from the table owner (the application's own database role).
-- +goose StatementBegin
CREATE FUNCTION audit_log_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change();

-- +goose Down
DROP TABLE audit_log;
DROP FUNCTION audit_log_reject_change();
DROP TABLE device_authorizations;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE invitations;
DROP TABLE memberships;
DROP TABLE workspaces;
DROP TABLE users;
DROP TYPE device_status;
DROP TYPE workspace_role;
