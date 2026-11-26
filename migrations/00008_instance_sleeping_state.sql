-- The "sleeping" instance state, in a migration of its own because
-- Postgres cannot use an enum value in the transaction that adds it, and
-- 00009 uses it in indexes.

-- +goose Up
ALTER TYPE instance_state ADD VALUE IF NOT EXISTS 'sleeping';

-- +goose Down
-- Postgres cannot drop enum values. The value stays unused once 00009 is
-- rolled back, which turns sleeping instances into stopped ones.
SELECT 1;
