-- Routes, access policies, visitor sign-in and gateway certificates.

-- name: ListRoutes :many
-- Every live app with where it is served: the newest instance of its
-- current deployment (or none).
SELECT a.id AS app_id, a.slug AS app_slug, w.id AS workspace_id, w.slug AS workspace_slug,
       a.access_mode, a.desired_state, a.current_deployment_id,
       coalesce(i.state::text, '')::text AS instance_state, coalesce(i.address, '')::text AS address, i.host_port
FROM apps a
JOIN workspaces w ON w.id = a.workspace_id
LEFT JOIN LATERAL (
    SELECT state, address, host_port FROM app_instances
    WHERE deployment_id = a.current_deployment_id
    ORDER BY created_at DESC
    LIMIT 1
) i ON true
WHERE a.deleted_at IS NULL
ORDER BY a.id;

-- name: GetRoute :one
SELECT a.id AS app_id, a.slug AS app_slug, w.id AS workspace_id, w.slug AS workspace_slug,
       a.access_mode, a.desired_state, a.current_deployment_id,
       coalesce(i.state::text, '')::text AS instance_state, coalesce(i.address, '')::text AS address, i.host_port
FROM apps a
JOIN workspaces w ON w.id = a.workspace_id
LEFT JOIN LATERAL (
    SELECT state, address, host_port FROM app_instances
    WHERE deployment_id = a.current_deployment_id
    ORDER BY created_at DESC
    LIMIT 1
) i ON true
WHERE a.id = @app_id AND a.deleted_at IS NULL;

-- name: GetAppBySlugs :one
-- A live app by workspace and app slug (from an app host name).
SELECT a.* FROM apps a JOIN workspaces w ON w.id = a.workspace_id
WHERE w.slug = @workspace_slug AND a.slug = @app_slug AND a.deleted_at IS NULL;

-- name: SetAccessMode :one
UPDATE apps SET access_mode = @access_mode WHERE id = @id AND deleted_at IS NULL RETURNING *;

-- name: ListAccessGrants :many
SELECT * FROM app_access_grants WHERE app_id = @app_id ORDER BY email;

-- name: CountAccessGrants :one
SELECT count(*)::integer FROM app_access_grants WHERE app_id = @app_id;

-- name: AddAccessGrant :execrows
INSERT INTO app_access_grants (app_id, email, granted_by) VALUES (@app_id, @email, @granted_by)
ON CONFLICT (app_id, email) DO NOTHING;

-- name: DeleteAccessGrant :execrows
DELETE FROM app_access_grants WHERE app_id = @app_id AND email = @email;

-- name: AccessGranted :one
SELECT EXISTS (SELECT 1 FROM app_access_grants WHERE app_id = @app_id AND email = @email) AS granted;

-- name: MemberRoleByEmail :one
-- The workspace role of the enabled user with this email.
SELECT m.role FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.workspace_id = @workspace_id AND u.email = @email AND u.disabled_at IS NULL;

-- name: CreateVisitorSession :one
INSERT INTO visitor_sessions (token_hash, host, app_id, email, name, issuer, subject, idle_expires_at, absolute_expires_at)
VALUES (@token_hash, @host, @app_id, @email, @name, @issuer, @subject, @idle_expires_at, @absolute_expires_at)
RETURNING *;

-- name: GetVisitorSession :one
-- A valid session by token hash.
SELECT * FROM visitor_sessions
WHERE token_hash = @token_hash AND revoked_at IS NULL AND idle_expires_at > now() AND absolute_expires_at > now();

-- name: TouchVisitorSession :exec
-- Extends the idle timeout (at most once a minute, within the absolute one).
UPDATE visitor_sessions
SET last_seen_at = now(), idle_expires_at = least(now() + make_interval(secs => @idle_seconds::double precision), absolute_expires_at)
WHERE id = @id AND last_seen_at < now() - interval '1 minute';

-- name: RevokeVisitorSession :exec
UPDATE visitor_sessions SET revoked_at = now() WHERE token_hash = @token_hash AND revoked_at IS NULL;

-- name: CreateVisitorCode :exec
INSERT INTO visitor_codes (code_hash, host, app_id, email, name, issuer, subject, return_path, expires_at)
VALUES (@code_hash, @host, @app_id, @email, @name, @issuer, @subject, @return_path, @expires_at);

-- name: UseVisitorCode :one
-- Redeems a code once, on the host it was issued for, before it expires.
UPDATE visitor_codes SET used_at = now()
WHERE code_hash = @code_hash AND host = @host AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredVisitorSessions :execrows
DELETE FROM visitor_sessions WHERE absolute_expires_at < now() - interval '1 day' OR revoked_at < now() - interval '1 day';

-- name: DeleteExpiredVisitorCodes :execrows
DELETE FROM visitor_codes WHERE expires_at < now() - interval '1 hour';

-- name: GetGatewayCertificate :one
SELECT * FROM gateway_certificates WHERE name = @name;

-- name: PutGatewayCertificate :exec
INSERT INTO gateway_certificates (name, data, key_version, updated_at) VALUES (@name, @data, @key_version, now())
ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, key_version = EXCLUDED.key_version, updated_at = now();

-- name: DeleteGatewayCertificate :exec
DELETE FROM gateway_certificates WHERE name = @name;

-- name: ListGatewayCertificatesNotOnVersion :many
SELECT name, data, key_version FROM gateway_certificates WHERE key_version <> @version ORDER BY name LIMIT @row_limit;

-- name: ReencryptGatewayCertificate :execrows
UPDATE gateway_certificates SET data = @data, key_version = @key_version WHERE name = @name AND key_version = @old_version;
