-- Deployment statuses for running apps. They are added in a migration of
-- their own because Postgres cannot use an enum value in the transaction
-- that adds it, and 00006 uses them in constraints and indexes.

-- +goose Up
ALTER TYPE deployment_status ADD VALUE IF NOT EXISTS 'deploying';
ALTER TYPE deployment_status ADD VALUE IF NOT EXISTS 'live';
ALTER TYPE deployment_status ADD VALUE IF NOT EXISTS 'superseded';
ALTER TYPE deployment_status ADD VALUE IF NOT EXISTS 'rolled_back';

-- +goose Down
-- Postgres cannot drop enum values. The values stay unused once 00006 is
-- rolled back, which resets every deployment that held one of them.
SELECT 1;
