-- name: DeleteExpiredOpenInvitation :exec
-- An expired invitation must not block re-inviting the same address.
DELETE FROM invitations
WHERE workspace_id = @workspace_id AND email = @email AND accepted_at IS NULL AND expires_at <= now();

-- name: CreateInvitation :one
INSERT INTO invitations (workspace_id, email, role, invited_by, expires_at)
VALUES (@workspace_id, @email, @role, @invited_by, now() + make_interval(secs => @ttl_seconds::float8))
RETURNING *;

-- name: ListOpenInvitations :many
SELECT * FROM invitations
WHERE workspace_id = @workspace_id AND accepted_at IS NULL AND expires_at > now() AND id > @after_id
ORDER BY id
LIMIT @row_limit;

-- name: DeleteOpenInvitation :one
DELETE FROM invitations
WHERE id = @id AND workspace_id = @workspace_id AND accepted_at IS NULL
RETURNING *;

-- name: HasOpenInvitation :one
SELECT EXISTS (
    SELECT 1 FROM invitations WHERE email = @email AND accepted_at IS NULL AND expires_at > now()
);

-- name: AcceptOpenInvitations :many
UPDATE invitations SET accepted_at = now()
WHERE email = @email AND accepted_at IS NULL AND expires_at > now()
RETURNING *;
