-- Extensions later stages rely on:
--   citext   case-insensitive text, for email addresses and slugs.
--   pgcrypto digest() and hmac() for hashing API tokens inside the database.
-- Both are "trusted" extensions (PostgreSQL 13+), so the database owner can
-- create them without superuser rights.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- +goose Down
DROP EXTENSION IF EXISTS pgcrypto;
DROP EXTENSION IF EXISTS citext;
