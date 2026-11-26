-- Sleep, wake and failover: idle apps sleep (their instance stops, its
-- container is kept for a fast wake, its reservation is released), a
-- request or `nook apps wake` wakes them, instances on dead or drained
-- nodes are replaced elsewhere.

-- +goose Up
ALTER TABLE apps
    -- NULL: the app never sleeps (sleep_after = "never" in nook.toml).
    ADD COLUMN sleep_after_seconds integer DEFAULT 900,
    -- Set while the app sleeps; why it was put to sleep.
    ADD COLUMN sleeping_since timestamptz,
    ADD COLUMN sleep_reason text NOT NULL DEFAULT '',
    -- The last request the gateways saw when the app went to sleep (live
    -- activity is in Redis).
    ADD COLUMN last_request_at timestamptz,
    -- Set by the one wake that won the compare-and-set; cleared when the
    -- woken instance is healthy.
    ADD COLUMN wake_requested_at timestamptz,
    ADD CONSTRAINT apps_sleep_after_positive CHECK (sleep_after_seconds IS NULL OR sleep_after_seconds > 0),
    ADD CONSTRAINT apps_sleep_reason_values CHECK (sleep_reason IN ('', 'idle', 'evicted')),
    ADD CONSTRAINT apps_sleeping_has_reason CHECK ((sleeping_since IS NULL) = (sleep_reason = ''));

ALTER TABLE app_instances
    -- Why the instance was created, and when that happened (the wake
    -- request, the node's death, the drain): measures wake and failover
    -- times.
    ADD COLUMN cause text NOT NULL DEFAULT 'release',
    ADD COLUMN cause_at timestamptz,
    -- Why it was asked to stop (shown to users; drives failover causes).
    ADD COLUMN stop_reason text NOT NULL DEFAULT '',
    ADD CONSTRAINT app_instances_cause_values CHECK (cause IN ('release', 'restart', 'wake', 'failover', 'drain')),
    ADD CONSTRAINT app_instances_stop_reason_values CHECK (stop_reason IN ('', 'replaced', 'stopped', 'sleep', 'evicted', 'failover', 'drain', 'deleted'));

-- A deployment may now run two instances at once while it moves to
-- another node (the old one serves until the new one is healthy); only
-- one may be starting.
DROP INDEX app_instances_one_running_per_deployment;
CREATE UNIQUE INDEX app_instances_one_starting_per_deployment ON app_instances (deployment_id)
    WHERE state = 'starting';
-- An app has at most one sleeping instance (its kept container).
CREATE UNIQUE INDEX app_instances_one_sleeping_per_app ON app_instances (app_id)
    WHERE state = 'sleeping';

-- +goose Down
UPDATE app_instances SET state = 'stopped', stopped_at = coalesce(stopped_at, now()) WHERE state = 'sleeping';
DROP INDEX app_instances_one_sleeping_per_app;
DROP INDEX app_instances_one_starting_per_deployment;
-- Of two running instances of a deployment, the older one stops.
UPDATE app_instances i SET state = 'stopping', stop_requested_at = now()
WHERE i.state IN ('starting', 'healthy', 'unhealthy') AND EXISTS (
    SELECT 1 FROM app_instances n
    WHERE n.deployment_id = i.deployment_id AND n.state IN ('starting', 'healthy', 'unhealthy') AND n.created_at > i.created_at
);
CREATE UNIQUE INDEX app_instances_one_running_per_deployment ON app_instances (deployment_id)
    WHERE state IN ('starting', 'healthy', 'unhealthy');
ALTER TABLE app_instances
    DROP CONSTRAINT app_instances_stop_reason_values,
    DROP CONSTRAINT app_instances_cause_values,
    DROP COLUMN stop_reason,
    DROP COLUMN cause_at,
    DROP COLUMN cause;
ALTER TABLE apps
    DROP CONSTRAINT apps_sleeping_has_reason,
    DROP CONSTRAINT apps_sleep_reason_values,
    DROP CONSTRAINT apps_sleep_after_positive,
    DROP COLUMN wake_requested_at,
    DROP COLUMN last_request_at,
    DROP COLUMN sleep_reason,
    DROP COLUMN sleeping_since,
    DROP COLUMN sleep_after_seconds;
