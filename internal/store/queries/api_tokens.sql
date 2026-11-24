-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, name, token_hash, prefix, expires_at)
VALUES (@user_id, @name, @token_hash, @prefix, @expires_at)
RETURNING *;

-- name: GetActiveAPIToken :one
SELECT sqlc.embed(t), sqlc.embed(u)
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = @token_hash
  AND t.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > now())
  AND u.disabled_at IS NULL;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = now()
WHERE id = @id
  AND (last_used_at IS NULL OR last_used_at < now() - make_interval(secs => @min_interval_seconds::float8));

-- name: ListAPITokens :many
-- Newest first; revoked tokens are hidden, expired ones are shown so users
-- can see why a script stopped working.
SELECT * FROM api_tokens
WHERE user_id = @user_id AND revoked_at IS NULL AND id < @before_id
ORDER BY id DESC
LIMIT @row_limit;

-- name: RevokeAPIToken :one
UPDATE api_tokens SET revoked_at = now()
WHERE id = @id AND user_id = @user_id AND revoked_at IS NULL
RETURNING *;
