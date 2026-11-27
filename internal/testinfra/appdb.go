//go:build integration

package testinfra

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"
)

// PostgresServerImage is the tag tests build deploy/docker/nook-postgres.Dockerfile as.
const PostgresServerImage = "nook-postgres:it"

var postgresImage struct {
	mu  sync.Mutex
	ok  bool
	err error
}

// BuildPostgresServerImage builds the app database server image for this
// machine's platform, once per test process. Docker's build cache makes
// later builds instant; only the first one downloads the base image and
// the WAL-G release (checked against its pinned SHA-256).
func BuildPostgresServerImage(ctx context.Context) (string, error) {
	postgresImage.mu.Lock()
	defer postgresImage.mu.Unlock()
	if postgresImage.ok {
		return PostgresServerImage, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	root := RepoRoot()
	cmd := exec.CommandContext(ctx, "docker", "buildx", "build", "--load", "--quiet", //nolint:gosec // G204: fixed arguments.
		"--file", filepath.Join(root, "deploy", "docker", "nook-postgres.Dockerfile"),
		"--tag", PostgresServerImage, root)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build %s: %w: %s", PostgresServerImage, err, strings.TrimSpace(string(out)))
	}
	postgresImage.ok = true
	return PostgresServerImage, nil
}

// DatabaseHost is how containers and the test process reach a port an
// agent publishes for the app database server on this machine.
type DatabaseHost struct {
	// Publish is the address the port is bound to (NOOK_AGENT_DB_PUBLISH_ADDR).
	Publish string
	// App is where app containers connect (NOOK_AGENT_DB_ADDR).
	App string
	// Admin is where the control plane connects (NOOK_APPDB_ADMIN_HOST).
	Admin string
}

// DatabaseHostAddrs picks the addresses for the local Docker engine. Docker
// Desktop publishes ports on the host side: bind 127.0.0.1, which
// containers reach as the host gateway. A native engine binds its bridge
// gateway address, reachable from containers and the host alike.
func DatabaseHostAddrs(ctx context.Context) (DatabaseHost, error) {
	d, err := client.New(client.FromEnv)
	if err != nil {
		return DatabaseHost{}, fmt.Errorf("docker client: %w", err)
	}
	defer func() { _ = d.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	info, err := d.Info(ctx, client.InfoOptions{})
	if err != nil {
		return DatabaseHost{}, fmt.Errorf("docker info: %w", err)
	}
	if strings.Contains(info.Info.OperatingSystem, "Docker Desktop") {
		return DatabaseHost{Publish: "127.0.0.1", App: "host-gateway", Admin: "127.0.0.1"}, nil
	}
	nw, err := d.NetworkInspect(ctx, "bridge", client.NetworkInspectOptions{})
	if err != nil {
		return DatabaseHost{}, fmt.Errorf("inspect the bridge network: %w", err)
	}
	for _, c := range nw.Network.IPAM.Config {
		if gw := c.Gateway; gw.IsValid() && gw.Is4() {
			a := gw.String()
			return DatabaseHost{Publish: a, App: a, Admin: a}, nil
		}
	}
	return DatabaseHost{}, errors.New("the bridge network has no IPv4 gateway")
}
