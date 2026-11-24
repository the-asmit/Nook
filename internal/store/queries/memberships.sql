-- name: CreateMembership :execrows
-- Joining an existing membership keeps the current role.
INSERT INTO memberships (workspace_id, user_id, role)
VALUES (@workspace_id, @user_id, @role)
ON CONFLICT (workspace_id, user_id) DO NOTHING;

-- name: GetMemberRole :one
SELECT role FROM memberships WHERE workspace_id = @workspace_id AND user_id = @user_id;

-- name: CountWorkspaceOwners :one
SELECT count(*) FROM memberships WHERE workspace_id = @workspace_id AND role = 'owner';

-- name: CountUserMemberships :one
SELECT count(*) FROM memberships WHERE user_id = @user_id;

-- name: ListWorkspaceMembers :many
SELECT u.id, u.email, u.name, u.avatar_url, m.role, m.created_at
FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.workspace_id = @workspace_id
  AND (u.email, u.id) > (@after_email::citext, @after_id::uuid)
ORDER BY u.email, u.id
LIMIT @row_limit;

-- name: IsWorkspaceMemberByEmail :one
SELECT EXISTS (
    SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
    WHERE m.workspace_id = @workspace_id AND u.email = @email
);

-- name: UpdateMemberRole :execrows
UPDATE memberships SET role = @role WHERE workspace_id = @workspace_id AND user_id = @user_id;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE workspace_id = @workspace_id AND user_id = @user_id;
