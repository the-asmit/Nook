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
