package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool creates a connection pool. It does not wait for the database to
// be reachable; callers use Ping (or health.WaitUntil) for that, so
// startup can retry with a deadline instead of failing on the first try.
func NewPool(ctx context.Context, cfg *Config, applicationName string) (*pgxpool.Pool, error) {
	pc, err := cfg.poolConfig(applicationName)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	return pool, nil
}
