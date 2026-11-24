-- name: CreateDeviceAuthorization :one
INSERT INTO device_authorizations (device_code_hash, user_code, client_name, expires_at, poll_interval_seconds)
VALUES (@device_code_hash, @user_code, @client_name, now() + make_interval(secs => @ttl_seconds::float8), @poll_interval_seconds)
RETURNING *;

-- name: GetDeviceAuthorizationForPoll :one
-- Locks the row so concurrent polls serialize; time comparisons use the
-- database clock only.
SELECT sqlc.embed(d),
       (d.expires_at <= now())::boolean AS is_expired,
       (d.last_polled_at IS NOT NULL
        AND d.last_polled_at > now() - make_interval(secs => d.poll_interval_seconds))::boolean AS polled_too_soon
FROM device_authorizations d
WHERE d.device_code_hash = @device_code_hash
FOR UPDATE;

-- name: MarkDeviceAuthorizationExpired :exec
UPDATE device_authorizations SET status = 'expired' WHERE id = @id AND status = 'pending';

-- name: RecordDevicePoll :exec
UPDATE device_authorizations
SET last_polled_at = now(), poll_interval_seconds = @poll_interval_seconds
WHERE id = @id;

-- name: ConsumeDeviceAuthorization :execrows
UPDATE device_authorizations SET status = 'consumed', api_token_id = @api_token_id
WHERE id = @id AND status = 'approved';

-- name: GetPendingDeviceAuthorization :one
SELECT * FROM device_authorizations
WHERE user_code = @user_code AND status = 'pending' AND expires_at > now();

-- name: DecideDeviceAuthorization :one
UPDATE device_authorizations SET status = @status, user_id = @user_id
WHERE user_code = @user_code AND status = 'pending' AND expires_at > now()
RETURNING *;
