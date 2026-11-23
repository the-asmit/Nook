//go:build integration

// Package testinfra starts real dependencies (PostgreSQL, Redis) in Docker
// for integration tests through testcontainers-go.
package testinfra

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// Images match deploy/compose/docker-compose.dev.yml exactly (a test
// enforces it), so tests exercise the same versions developers run.
const (
	PostgresImage = "postgres:18.7-trixie@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a"
	RedisImage    = "redis:8.10.3-alpine3.23@sha256:7958cfbb9d152f87dadfbc89f1b0b15938f0b81ff8982feb327476f4911935c3"
)

// startTimeout bounds pulling an image and waiting for a container to be ready.
const startTimeout = 3 * time.Minute

// StartPostgres runs a PostgreSQL container and returns it with a
// connection URL for its superuser. Callers must Terminate it.
func StartPostgres(ctx context.Context) (*tcpostgres.PostgresContainer, string, error) {
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	c, err := tcpostgres.Run(ctx, PostgresImage,
		tcpostgres.WithDatabase("nook"),
		tcpostgres.WithUsername("nook"),
		tcpostgres.WithPassword(rand.Text()),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		if c != nil {
			_ = testcontainers.TerminateContainer(c)
		}
		return nil, "", fmt.Errorf("start postgres container: %w", err)
	}
	connURL, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, "", fmt.Errorf("postgres connection string: %w", err)
	}
	return c, connURL, nil
}

// PostgresT starts a PostgreSQL container owned by test t.
func PostgresT(tb testing.TB) (*tcpostgres.PostgresContainer, string) {
	tb.Helper()
	c, connURL, err := StartPostgres(context.Background())
	testcontainers.CleanupContainer(tb, c)
	if err != nil {
		tb.Fatal(err)
	}
	return c, connURL
}

// RedisT starts a Redis container owned by test t and returns its URL.
func RedisT(tb testing.TB) (*tcredis.RedisContainer, string) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	c, err := tcredis.Run(ctx, RedisImage)
	testcontainers.CleanupContainer(tb, c)
	if err != nil {
		tb.Fatalf("start redis container: %v", err)
	}
	connURL, err := c.ConnectionString(ctx)
	if err != nil {
		tb.Fatalf("redis connection string: %v", err)
	}
	return c, connURL
}

// CreateDatabase creates an empty database on the server behind adminURL
// and returns a URL for it, giving each test an isolated schema.
func CreateDatabase(tb testing.TB, adminURL string) string {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		tb.Fatalf("connect as admin: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	name := "test_" + strings.ToLower(rand.Text())
	_, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	if err != nil {
		tb.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		tb.Fatalf("parse admin URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// Pause freezes a container's processes, simulating a dependency that
// accepts connections but never answers. It returns a function that
// resumes the container; t's cleanup also resumes it if still paused.
func Pause(tb testing.TB, c testcontainers.Container) (unpause func()) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		tb.Fatalf("docker client: %v", err)
	}
	id := c.GetContainerID()
	if _, err := cli.ContainerPause(ctx, id, client.ContainerPauseOptions{}); err != nil {
		tb.Fatalf("pause container: %v", err)
	}
	paused := true
	unpause = func() {
		if !paused {
			return
		}
		paused = false
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := cli.ContainerUnpause(ctx, id, client.ContainerUnpauseOptions{}); err != nil {
			tb.Errorf("unpause container: %v", err)
		}
	}
	tb.Cleanup(func() {
		unpause()
		_ = cli.Close()
	})
	return unpause
}
