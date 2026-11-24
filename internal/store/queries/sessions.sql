-- name: CreateSession :one
INSERT INTO sessions (user_id, token_hash, idle_expires_at, absolute_expires_at, user_agent, ip)
VALUES (
    @user_id, @token_hash,
    now() + make_interval(secs => @idle_seconds::float8),
    now() + make_interval(secs => @absolute_seconds::float8),
    @user_agent, @ip
)
RETURNING *;

-- name: GetActiveSession :one
SELECT sqlc.embed(s), sqlc.embed(u)
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = @token_hash
  AND s.revoked_at IS NULL
  AND s.idle_expires_at > now()
  AND s.absolute_expires_at > now()
  AND u.disabled_at IS NULL;

-- name: TouchSession :exec
-- Slides the idle expiry forward, at most once per min_interval_seconds to
-- keep reads from turning into a write per request.
UPDATE sessions
SET last_seen_at = now(),
    idle_expires_at = LEAST(now() + make_interval(secs => @idle_seconds::float8), absolute_expires_at)
WHERE id = @id AND last_seen_at < now() - make_interval(secs => @min_interval_seconds::float8);

-- name: RevokeSession :execrows
UPDATE sessions SET revoked_at = now() WHERE id = @id AND revoked_at IS NULL;

-- name: RevokeSessionByTokenHash :execrows
UPDATE sessions SET revoked_at = now() WHERE token_hash = @token_hash AND revoked_at IS NULL;
