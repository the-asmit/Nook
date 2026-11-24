-- name: GetUserByIdentity :one
SELECT * FROM users
WHERE oidc_issuer = @oidc_issuer AND oidc_subject = @oidc_subject;

-- name: CreateUser :one
INSERT INTO users (email, name, avatar_url, oidc_issuer, oidc_subject, is_instance_admin, last_login_at)
VALUES (@email, @name, @avatar_url, @oidc_issuer, @oidc_subject, @is_instance_admin, now())
RETURNING *;

-- name: RecordUserSignIn :one
-- Refreshes profile data from the identity provider. Instance-admin status
-- can be granted here (bootstrap admins) but never revoked implicitly.
UPDATE users
SET email = @email,
    name = @name,
    avatar_url = @avatar_url,
    last_login_at = now(),
    is_instance_admin = is_instance_admin OR @grant_instance_admin::boolean
WHERE id = @id
RETURNING *;

-- name: ListUsers :many
SELECT * FROM users
WHERE email > @after_email::citext
  AND (@email_filter::citext = '' OR email = @email_filter::citext)
ORDER BY email
LIMIT @row_limit;

-- name: LockUser :one
SELECT * FROM users WHERE id = @id FOR UPDATE;

-- name: CountEnabledInstanceAdmins :one
SELECT count(*) FROM users WHERE is_instance_admin AND disabled_at IS NULL;

-- name: SetUserDisabled :one
UPDATE users
SET disabled_at = CASE WHEN @disabled::boolean THEN coalesce(disabled_at, now()) ELSE NULL END
WHERE id = @id
RETURNING *;

-- name: LockUserAdministration :exec
-- Serializes enable/disable decisions so two admins disabling each other
-- at the same moment cannot leave the installation without an admin.
SELECT pg_advisory_xact_lock(7957695015192413556);
