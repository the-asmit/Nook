//go:build integration && internet

package server

// Tests that need the public internet: base images from Docker Hub and
// gcr.io, public DNS names. They are not part of `make test-integration`
// (which must not depend on anything outside this machine); run them with
// `make test-e2e-internet`, which CI does on a schedule and before every
// release. Their names start with TestE2E.

import (
	"context"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/testinfra"
)

// TestE2EDeployExampleWithTheCLI is the whole pipeline: `nook deploy` in
// examples/hello-go packs, uploads straight to storage, follows the live
// build log of a real agent building with BuildKit, stores the image in
// the registry by digest, releases it and ends when it is live and
// answering on its node.
func TestE2EDeployExampleWithTheCLI(t *testing.T) {
	b := startBuildEnv(t, nil)
	cli := b.cliFor(b.alice)
	dir := filepath.Join(testinfra.RepoRoot(), "examples", "hello-go")

	code, stdout, stderr := cli.run("deploy", "--dir", dir)
	if code != 0 {
		t.Fatalf("nook deploy exited %d\nstdout:\n%s\nstderr:\n%s\nserver logs:\n%s", code, stdout, stderr, b.logs.String())
	}
	for _, want := range []string{"Created app hello-go", "Packed", "Uploaded", "Deployment #1"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if n := strings.Count(stderr, "queued"); n != 1 {
		t.Errorf("the queued status is printed %d times:\n%s", n, stderr)
	}
	for _, want := range []string{"go build", "Image: " + shared.storage.Registry.NetworkAddr + "/", "[nook] releasing deployment #1",
		"Deployment #1 of hello-go is live.", "serving at http://127.0.0.1:"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout lacks %q:\n%s", want, stdout)
		}
	}

	d := b.deployment(b.alice, b.ws, "hello-go", 1)
	if d.Status != "live" || d.ImageDigest == nil || len(d.Builds) != 1 || *d.Builds[0].Result != "succeeded" || d.Builds[0].Node != "builder-1" {
		t.Fatalf("deployment %+v", d)
	}
	r := &runtimeEnv{buildEnv: b}
	if status, body := get(r.appBase(b.alice, b.ws, "hello-go") + "/"); status != 200 || !strings.Contains(body, "Hello from a Nook app") {
		t.Fatalf("the app answers %d %q", status, body)
	}
	code, stdout, _ = cli.run("apps", "info", "hello-go")
	if code != 0 || !strings.Contains(stdout, "Health:       running") || !strings.Contains(stdout, "Live:         #1") {
		t.Fatalf("apps info: %d\n%s", code, stdout)
	}
	var app struct {
		ID string `json:"id"`
	}
	b.as(b.alice, http.MethodGet, appURL(b.ws, "hello-go"), nil).json(t, &app)
	var wsID string
	if err := b.db.QueryRow(context.Background(), "SELECT workspace_id::text FROM apps WHERE id = $1", app.ID).Scan(&wsID); err != nil {
		t.Fatal(err)
	}
	ok, err := registryClient(t).ManifestExists(context.Background(), wsID+"/"+app.ID, *d.ImageDigest)
	if err != nil || !ok {
		t.Fatalf("image %s not in the registry: %v", *d.ImageDigest, err)
	}

	code, stdout, _ = cli.run("deployments", "list", "hello-go")
	if code != 0 || !strings.Contains(stdout, "live") {
		t.Fatalf("deployments list: %d\n%s", code, stdout)
	}
	code, stdout, _ = cli.run("build-logs", "hello-go")
	if code != 0 || !strings.Contains(stdout, "[nook] pushed") {
		t.Fatalf("build-logs: %d\n%s", code, stdout)
	}
	// The stored log is served once the live stream is gone.
	b.flushBuildLogStreams()
	if log := b.buildLog(b.alice, b.ws, "hello-go", 1); !strings.Contains(log, "[nook] pushed") {
		t.Fatalf("stored log:\n%s", log)
	}
}

// TestE2EAppsAndBuildsResolvePublicNames: apps and build steps resolve a
// public name through the node's resolvers, which the egress firewall
// allows, while the metadata address stays blocked for HTTP.
func TestE2EAppsAndBuildsResolvePublicNames(t *testing.T) {
	name := firstResolvable(t, "github.com", "registry-1.docker.io")
	if name == "" {
		t.Fatal("no public name resolves from a plain container; is this machine online?")
	}
	startStandIn(t, "nook-test-metadata", "169.254.169.0/24", metadataStandIn)
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	base := r.appBase(r.alice, r.ws, "web")
	appResolves(t, base, name)
	if _, body := get(base + "/fetch?url=http://" + metadataStandIn + "/"); !strings.HasPrefix(body, "error") {
		t.Fatalf("metadata stand-in reachable from the app: %q", body)
	}

	r.createApp(r.alice, r.ws, "probe")
	n := r.deploy(r.alice, r.ws, "probe", project(t, map[string]string{"Dockerfile": "FROM __BASE__\n" + dnsProbe(name)}))
	d := r.waitStatus(r.alice, r.ws, "probe", n, 3*time.Minute, "built", "failed")
	log := r.buildLog(r.alice, r.ws, "probe", n)
	if d.Status != "built" || !regexp.MustCompile(`(?m)^#\d+ \d+\.\d+ DNS-RESOLVED$`).MatchString(log) {
		t.Fatalf("deployment %s; a build step did not resolve %s:\n%s", d.Status, name, log)
	}
}

// flushBuildLogStreams drops the live log streams, as their expiry would.
func (b *buildEnv) flushBuildLogStreams() {
	b.t.Helper()
	rdb := redisClient(b.t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keys, err := rdb.Keys(ctx, "nook:build-log:*").Result()
	if err != nil {
		b.t.Fatal(err)
	}
	if len(keys) > 0 {
		if err := rdb.Del(ctx, keys...).Err(); err != nil {
			b.t.Fatal(err)
		}
	}
}
