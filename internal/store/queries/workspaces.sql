-- name: CreateWorkspace :one
INSERT INTO workspaces (name, slug, personal_owner_id)
VALUES (@name, @slug, @personal_owner_id)
RETURNING *;

-- name: WorkspaceSlugExists :one
SELECT EXISTS (SELECT 1 FROM workspaces WHERE slug = @slug);

-- name: GetWorkspaceForMember :one
-- Tenant isolation: a workspace is only visible through the caller's own
-- membership, so "not a member" and "does not exist" are indistinguishable.
SELECT sqlc.embed(w), m.role
FROM workspaces w
JOIN memberships m ON m.workspace_id = w.id
WHERE w.slug = @slug AND m.user_id = @user_id;

-- name: ListWorkspacesForMember :many
SELECT sqlc.embed(w), m.role
FROM workspaces w
JOIN memberships m ON m.workspace_id = w.id
WHERE m.user_id = @user_id AND w.slug > @after_slug
ORDER BY w.slug
LIMIT @row_limit;

-- name: LockWorkspace :one
-- Serializes membership changes in one workspace so concurrent requests
-- cannot together remove its last owner.
SELECT id FROM workspaces WHERE id = @id FOR UPDATE;

-- name: RenameWorkspace :one
UPDATE workspaces SET name = @name WHERE id = @id RETURNING *;

-- name: DeleteWorkspace :exec
DELETE FROM workspaces WHERE id = @id;
