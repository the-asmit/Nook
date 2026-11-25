//go:build integration

package testinfra

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"
)

// DexImage matches deploy/compose/docker-compose.dev.yml (a test enforces it).
const DexImage = "ghcr.io/dexidp/dex:v2.46.1@sha256:65b72ca0f4b0bf6d4ada84ec21da8851782563404ac7b8f926923d27ceced9ab"

// The static users defined in deploy/compose/dex/config.yaml.
const (
	DexAlice   = "alice@nook.test"
	DexBob     = "bob@partner.test"
	DexMallory = "mallory@outside.test"
)

// Dex is a running Dex development identity provider.
type Dex struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// Passwords maps each static user's email to their password.
	Passwords map[string]string
}

// RepoRoot locates the repository from this source file, so helpers work
// whatever package directory the test runs in.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// FreePort returns a TCP port on 127.0.0.1 that was free a moment ago.
// The OIDC issuer and redirect URLs must be fixed before the processes
// that serve them start, so their ports are chosen up front.
func FreePort() (int, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("find free port: %w", err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if err := ln.Close(); err != nil {
		return 0, fmt.Errorf("release port: %w", err)
	}
	if !ok {
		return 0, fmt.Errorf("unexpected listener address %v", ln.Addr())
	}
	return addr.Port, nil
}

// StartDex runs Dex with the repository's development configuration,
// accepting redirectURI for Nook. Callers must terminate the container.
func StartDex(ctx context.Context, port int, redirectURI string) (*Dex, testcontainers.Container, error) {
	d := &Dex{
		IssuerURL:    fmt.Sprintf("http://127.0.0.1:%d/dex", port),
		ClientID:     "nook-test",
		ClientSecret: rand.Text(),
		Passwords:    map[string]string{DexAlice: rand.Text(), DexBob: rand.Text(), DexMallory: rand.Text()},
	}
	env := map[string]string{
		"DEX_ISSUER":             d.IssuerURL,
		"DEX_NOOK_CLIENT_ID":     d.ClientID,
		"DEX_NOOK_CLIENT_SECRET": d.ClientSecret,
		"DEX_NOOK_REDIRECT_URI":  redirectURI,
	}
	for email, envName := range map[string]string{
		DexAlice: "DEX_ALICE_PASSWORD_HASH", DexBob: "DEX_BOB_PASSWORD_HASH", DexMallory: "DEX_MALLORY_PASSWORD_HASH",
	} {
		// Dex refuses hashes below bcrypt's default cost of 10.
		h, err := bcrypt.GenerateFromPassword([]byte(d.Passwords[email]), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, fmt.Errorf("hash password: %w", err)
		}
		env[envName] = string(h)
	}

	containerPort := network.MustParsePort("5556/tcp")
	ctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	c, err := testcontainers.Run(ctx, DexImage,
		testcontainers.WithCmd("dex", "serve", "/etc/dex/nook-dev.yaml"),
		testcontainers.WithEnv(env),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			HostFilePath:      filepath.Join(RepoRoot(), "deploy", "compose", "dex", "config.yaml"),
			ContainerFilePath: "/etc/dex/nook-dev.yaml",
			FileMode:          0o644,
		}),
		testcontainers.WithExposedPorts("5556/tcp"),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.PortBindings = network.PortMap{containerPort: {{
				HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: strconv.Itoa(port),
			}}}
		}),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/dex/.well-known/openid-configuration").WithPort("5556/tcp")),
	)
	if err != nil {
		if c != nil {
			_ = testcontainers.TerminateContainer(c)
		}
		return nil, nil, fmt.Errorf("start dex container: %w", err)
	}
	return d, c, nil
}
