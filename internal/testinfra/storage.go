//go:build integration

package testinfra

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Images match deploy/compose/docker-compose.dev.yml exactly (a test enforces it).
const (
	MinIOImage    = "cgr.dev/chainguard/minio:latest@sha256:bd92a45b821c0d85772c607ed7b49693efe78b3ffffae301b5d1b0981660de22"
	RegistryImage = "registry:3.1.2@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c"
)

// Network aliases on the shared test network, matching the service names
// of the development stack.
const (
	MinIOAlias    = "minio"
	RegistryAlias = "registry"
)

// Network is a Docker network for containers that talk to each other
// (registry → MinIO, build containers → registry).
type Network struct {
	*testcontainers.DockerNetwork
}

// NewNetwork creates a network; callers remove it.
func NewNetwork(ctx context.Context) (*Network, error) {
	nw, err := network.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}
	return &Network{DockerNetwork: nw}, nil
}

// MinIO is a running S3-compatible object store.
type MinIO struct {
	testcontainers.Container
	// URL is reachable from the test process (http://127.0.0.1:port).
	URL       string
	AccessKey string
	SecretKey string
}

// StartMinIO runs MinIO on nw under the alias "minio".
func StartMinIO(ctx context.Context, nw *Network) (*MinIO, error) {
	m := &MinIO{AccessKey: "nook", SecretKey: strings.ToLower(rand.Text())}
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	c, err := testcontainers.Run(ctx, MinIOImage,
		testcontainers.WithCmd("server", "/data"),
		testcontainers.WithEnv(map[string]string{"MINIO_ROOT_USER": m.AccessKey, "MINIO_ROOT_PASSWORD": m.SecretKey}),
		testcontainers.WithExposedPorts("9000/tcp"),
		network.WithNetwork([]string{MinIOAlias}, nw.DockerNetwork),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp")),
	)
	if err != nil {
		if c != nil {
			_ = testcontainers.TerminateContainer(c)
		}
		return nil, fmt.Errorf("start minio container: %w", err)
	}
	m.Container = c
	ep, err := c.PortEndpoint(ctx, "9000/tcp", "http")
	if err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, fmt.Errorf("minio endpoint: %w", err)
	}
	m.URL = strings.Replace(ep, "localhost", "127.0.0.1", 1)
	return m, nil
}

// CreateBucket creates a bucket with MinIO's own client inside the container.
func (m *MinIO) CreateBucket(ctx context.Context, name string) error {
	alias := fmt.Sprintf("http://%s:%s@127.0.0.1:9000", m.AccessKey, m.SecretKey)
	code, out, err := m.Exec(ctx, []string{"env", "MC_HOST_local=" + alias, "mc", "mb", "--ignore-existing", "local/" + name})
	if err != nil {
		return fmt.Errorf("create bucket %s: %w", name, err)
	}
	if code != 0 {
		return fmt.Errorf("create bucket %s: mc exited %d: %s", name, code, readAll(out))
	}
	return nil
}

// Registry is a running CNCF Distribution registry.
type Registry struct {
	testcontainers.Container
	// Addr is reachable from the test process (127.0.0.1:port).
	Addr string
	// NetworkAddr is reachable from containers on the test network.
	NetworkAddr string
}

// RegistryOptions configure StartRegistry.
type RegistryOptions struct {
	// CertDir holds tls.crt, tls.key and ca.crt (pki.WriteServerFiles).
	CertDir string
	// Bucket is the MinIO bucket for image data.
	Bucket string
}

// StartRegistry runs the registry with the repository's configuration
// (deploy/compose/registry/config.yml), storing images in MinIO.
func StartRegistry(ctx context.Context, nw *Network, m *MinIO, o RegistryOptions) (*Registry, error) {
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	var files []testcontainers.ContainerFile
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		// Inside the throwaway test container the key only needs to be
		// readable by the registry's non-root user.
		files = append(files, testcontainers.ContainerFile{
			HostFilePath: filepath.Join(o.CertDir, name), ContainerFilePath: "/certs/" + name, FileMode: 0o644,
		})
	}
	files = append(files, testcontainers.ContainerFile{
		HostFilePath:      filepath.Join(RepoRoot(), "deploy", "compose", "registry", "config.yml"),
		ContainerFilePath: "/etc/distribution/config.yml", FileMode: 0o644,
	})
	c, err := testcontainers.Run(ctx, RegistryImage,
		testcontainers.WithFiles(files...),
		testcontainers.WithEnv(map[string]string{
			"REGISTRY_STORAGE_S3_ACCESSKEY":      m.AccessKey,
			"REGISTRY_STORAGE_S3_SECRETKEY":      m.SecretKey,
			"REGISTRY_STORAGE_S3_REGIONENDPOINT": "http://" + MinIOAlias + ":9000",
			"REGISTRY_STORAGE_S3_BUCKET":         o.Bucket,
		}),
		testcontainers.WithConfigModifier(func(c *container.Config) { c.User = "65532:65532" }),
		testcontainers.WithExposedPorts("5000/tcp"),
		network.WithNetwork([]string{RegistryAlias}, nw.DockerNetwork),
		testcontainers.WithWaitStrategy(wait.ForLog("listening on")),
	)
	if err != nil {
		if c != nil {
			_ = testcontainers.TerminateContainer(c)
		}
		return nil, fmt.Errorf("start registry container: %w", err)
	}
	host, err := c.PortEndpoint(ctx, "5000/tcp", "")
	if err != nil {
		_ = testcontainers.TerminateContainer(c)
		return nil, fmt.Errorf("registry endpoint: %w", err)
	}
	return &Registry{Container: c, Addr: strings.Replace(host, "localhost", "127.0.0.1", 1), NetworkAddr: RegistryAlias + ":5000"}, nil
}

// GarbageCollect runs the registry's offline garbage collector inside the
// container, deleting blobs no manifest references any more.
func (r *Registry) GarbageCollect(ctx context.Context) (string, error) {
	code, out, err := r.Exec(ctx, []string{"registry", "garbage-collect", "--delete-untagged", "/etc/distribution/config.yml"})
	text := readAll(out)
	if err != nil {
		return text, fmt.Errorf("garbage-collect: %w", err)
	}
	if code != 0 {
		return text, fmt.Errorf("garbage-collect exited %d: %s", code, text)
	}
	return text, nil
}

// StorageT starts MinIO and the registry on a new network for test t.
type StorageT struct {
	Network  *Network
	MinIO    *MinIO
	Registry *Registry
}

// StartStorage runs MinIO (with the buckets) and the registry; the
// returned cleanup stops them.
func StartStorage(ctx context.Context, certDir string, buckets ...string) (*StorageT, func(), error) {
	nw, err := NewNetwork(ctx)
	if err != nil {
		return nil, nil, err
	}
	s := &StorageT{Network: nw}
	cleanup := func() {
		if s.Registry != nil {
			_ = testcontainers.TerminateContainer(s.Registry)
		}
		if s.MinIO != nil {
			_ = testcontainers.TerminateContainer(s.MinIO)
		}
		_ = nw.Remove(context.WithoutCancel(ctx))
	}
	if s.MinIO, err = StartMinIO(ctx, nw); err != nil {
		cleanup()
		return nil, nil, err
	}
	for _, b := range append(buckets, "nook-registry") {
		if err = s.MinIO.CreateBucket(ctx, b); err != nil {
			cleanup()
			return nil, nil, err
		}
	}
	if s.Registry, err = StartRegistry(ctx, nw, s.MinIO, RegistryOptions{CertDir: certDir, Bucket: "nook-registry"}); err != nil {
		cleanup()
		return nil, nil, err
	}
	return s, cleanup, nil
}

// MustStorage starts storage for one test.
func MustStorage(tb testing.TB, certDir string, buckets ...string) *StorageT {
	tb.Helper()
	s, cleanup, err := StartStorage(context.Background(), certDir, buckets...)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(cleanup)
	return s
}

func readAll(r io.Reader) string {
	if r == nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(r, 1<<20))
	return string(b)
}
