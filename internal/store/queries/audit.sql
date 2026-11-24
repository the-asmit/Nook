-- name: InsertAuditEntry :exec
INSERT INTO audit_log (workspace_id, actor_user_id, action, target_type, target_id, metadata, ip)
VALUES (@workspace_id, @actor_user_id, @action, @target_type, @target_id, @metadata, @ip);
