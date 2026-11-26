-- The gateway: app host names, access policies, visitor sign-in and the
-- certificates the gateway obtains.

-- +goose Up
-- App URLs are https://<app>--<workspace>.<apps domain>: "--" separates the
-- two slugs, so neither may contain it. Existing rows are checked first,
-- with a message that names them, rather than failing on a constraint.
-- +goose StatementBegin
DO $$
DECLARE
    offenders text;
BEGIN
    SELECT string_agg(kind || ' ' || slug, ', ') INTO offenders FROM (
        SELECT 'workspace' AS kind, slug FROM workspaces WHERE slug LIKE '%--%'
        UNION ALL
        SELECT 'app', slug FROM apps WHERE slug LIKE '%--%' AND deleted_at IS NULL
    ) s;
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION 'slugs may no longer contain "--" (it separates app and workspace in app host names); rename: %', offenders;
    END IF;
    SELECT string_agg(w.slug || '/' || a.slug, ', ') INTO offenders
    FROM apps a JOIN workspaces w ON w.id = a.workspace_id
    WHERE a.deleted_at IS NULL AND char_length(a.slug) + 2 + char_length(w.slug) > 63;
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION 'app host labels "<app>--<workspace>" must be at most 63 characters; rename: %', offenders;
    END IF;
END
$$;
-- +goose StatementEnd
ALTER TABLE workspaces ADD CONSTRAINT workspaces_slug_no_double_hyphen CHECK (slug NOT LIKE '%--%');
-- Deleted apps keep their old slugs until they are purged.
ALTER TABLE apps ADD CONSTRAINT apps_slug_no_double_hyphen CHECK (deleted_at IS NOT NULL OR slug NOT LIKE '%--%');

-- Who may open an app: workspace members (default), workspace admins and
-- owners plus granted emails, or anyone.
CREATE TYPE app_access_mode AS ENUM ('workspace', 'restricted', 'public');
ALTER TABLE apps ADD COLUMN access_mode app_access_mode NOT NULL DEFAULT 'workspace';

-- People given access by email, members or not (workspace and restricted
-- modes).
CREATE TABLE app_access_grants (
    app_id     uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    email      citext NOT NULL,
    granted_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, email),
    CONSTRAINT app_access_grants_email_length CHECK (char_length(email) BETWEEN 3 AND 254)
);

-- Visitor sessions: on the auth host (app_id NULL) and per app host. Only
-- a SHA-256 of the token is stored; the session is bound to its host.
CREATE TABLE visitor_sessions (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    token_hash          bytea NOT NULL,
    host                text NOT NULL,
    app_id              uuid REFERENCES apps (id) ON DELETE CASCADE,
    email               citext NOT NULL,
    name                text NOT NULL DEFAULT '',
    issuer              text NOT NULL,
    subject             text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at          timestamptz,
    CONSTRAINT visitor_sessions_token_hash_key UNIQUE (token_hash),
    CONSTRAINT visitor_sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT visitor_sessions_host_length CHECK (char_length(host) BETWEEN 1 AND 253),
    CONSTRAINT visitor_sessions_name_length CHECK (char_length(name) <= 200),
    CONSTRAINT visitor_sessions_idle_within_absolute CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX visitor_sessions_expiry_idx ON visitor_sessions (absolute_expires_at);

-- Codes the auth host hands to an app host's /_nook/callback: single use,
-- bound to that host, short-lived. The return path is stored here, not
-- taken from the callback URL.
CREATE TABLE visitor_codes (
    code_hash   bytea PRIMARY KEY,
    host        text NOT NULL,
    app_id      uuid NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    email       citext NOT NULL,
    name        text NOT NULL DEFAULT '',
    issuer      text NOT NULL,
    subject     text NOT NULL,
    return_path text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    CONSTRAINT visitor_codes_code_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT visitor_codes_return_path_format CHECK (return_path LIKE '/%' AND char_length(return_path) <= 2048)
);
CREATE INDEX visitor_codes_expiry_idx ON visitor_codes (expires_at);

-- Certificates and ACME account keys the gateways obtain, shared by every
-- gateway instance; sealed with the secrets keyring (they hold private keys).
CREATE TABLE gateway_certificates (
    name        text PRIMARY KEY,
    data        bytea NOT NULL,
    key_version integer NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT gateway_certificates_name_length CHECK (char_length(name) BETWEEN 1 AND 300)
);

-- +goose Down
DROP TABLE gateway_certificates;
DROP TABLE visitor_codes;
DROP TABLE visitor_sessions;
DROP TABLE app_access_grants;
ALTER TABLE apps DROP COLUMN access_mode;
DROP TYPE app_access_mode;
ALTER TABLE apps DROP CONSTRAINT apps_slug_no_double_hyphen;
ALTER TABLE workspaces DROP CONSTRAINT workspaces_slug_no_double_hyphen;
