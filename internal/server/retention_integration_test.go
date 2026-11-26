//go:build integration

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/testinfra"
)

// appRepo returns an app's ID and registry repository.
func (b *buildEnv) appRepo(ws, app string) (string, string) {
	b.t.Helper()
	var appID, wsID string
	if err := b.db.QueryRow(context.Background(), `SELECT a.id::text, a.workspace_id::text FROM apps a
		JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = $1 AND a.slug = $2`, ws, app).Scan(&appID, &wsID); err != nil {
		b.t.Fatal(err)
	}
	return appID, wsID + "/" + appID
}

func (b *buildEnv) janitorTick() {
	b.t.Helper()
	if err := b.primary.srv.janitor.Tick(context.Background()); err != nil {
		b.t.Fatalf("janitor: %v", err)
	}
}

func objects(t *testing.T) *objstore.Client {
	t.Helper()
	c, err := objstore.New(&objstore.Config{Endpoint: shared.storage.MinIO.URL, Region: "us-east-1", Bucket: "nook",
		AccessKeyID: shared.storage.MinIO.AccessKey, SecretAccessKey: config.NewSecret(shared.storage.MinIO.SecretKey),
		RequestTimeout: 10 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (b *buildEnv) gcWindow(action, secret string) response {
	b.t.Helper()
	req := newRequest(b.t, http.MethodPost, b.base+"/api/v1/registry/gc-window/"+action, jsonBody(b.t, map[string]int{"ttl_seconds": 300}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	return send(b.t, http.DefaultClient, req)
}

func TestImageRetentionAndRegistryGC(t *testing.T) {
	b := startBuildEnv(t, map[string]string{"NOOK_IMAGE_RETENTION_COUNT": "2"})
	b.createApp(b.alice, b.ws, "web")
	var digests []string
	for i := range 3 {
		n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile(fmt.Sprintf("image-%d", i))))
		d := b.waitStatus(b.alice, b.ws, "web", n, 3*time.Minute, "built")
		digests = append(digests, *d.ImageDigest)
	}
	_, repo := b.appRepo(b.ws, "web")
	reg := registryClient(t)
	b.janitorTick()

	if d := b.deployment(b.alice, b.ws, "web", 1); !d.ImageDeleted {
		t.Fatalf("oldest image kept: %+v", d)
	}
	for i, digest := range digests {
		ok, err := reg.ManifestExists(context.Background(), repo, digest)
		if err != nil || ok != (i > 0) {
			t.Fatalf("image %d exists=%v (%v)", i+1, ok, err)
		}
	}

	// Blob garbage collection runs in a maintenance window, during which
	// no build starts.
	if r := b.gcWindow("open", "wrong-secret-0123456789"); r.status != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", r.status)
	}
	if r := b.gcWindow("open", testGCSecret); r.status != http.StatusOK {
		t.Fatalf("open window: %d %s", r.status, r.body)
	}
	if r := b.gcWindow("open", testGCSecret); r.status != http.StatusConflict {
		t.Fatalf("second window: %d", r.status)
	}
	n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("after-gc")))
	// Observe the deployment for a while: it must stay queued.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if d := b.deployment(b.alice, b.ws, "web", n); d.Status != "queued" {
			t.Fatalf("a build started during the maintenance window: %+v", d)
		}
	}
	if out, err := shared.storage.Registry.GarbageCollect(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r := b.gcWindow("close", testGCSecret); r.status != http.StatusNoContent {
		t.Fatalf("close window: %d", r.status)
	}
	b.waitStatus(b.alice, b.ws, "web", n, 3*time.Minute, "built")
	for _, digest := range digests[1:] {
		if ok, _ := reg.ManifestExists(context.Background(), repo, digest); !ok {
			t.Fatal("garbage collection removed a kept image")
		}
	}
}

func TestDeletedAppIsPurged(t *testing.T) {
	b := startBuildEnv(t, nil)
	b.createApp(b.alice, b.ws, "doomed")
	n := b.deploy(b.alice, b.ws, "doomed", project(t, helloDockerfile("purge")))
	d := b.waitStatus(b.alice, b.ws, "doomed", n, 3*time.Minute, "built")
	appID, repo := b.appRepo(b.ws, "doomed")
	var sourceKey string
	var logKey *string
	// The attempt's log is stored just after the result is recorded.
	eventually(t, 30*time.Second, "the build log to be stored", func() bool {
		err := b.db.QueryRow(context.Background(), `SELECT d.source_key, b.log_key FROM deployments d JOIN builds b ON b.deployment_id = d.id
			WHERE d.app_id = $1`, appID).Scan(&sourceKey, &logKey)
		return err == nil && logKey != nil
	})
	reg := registryClient(t)
	if tags, err := reg.Tags(context.Background(), repo+"/cache"); err != nil || !slices.Contains(tags, apps.CacheTag) {
		t.Fatalf("no build cache before the purge: %v %v", tags, err)
	}
	expectStatus(t, b.as(b.alice, http.MethodDelete, appURL(b.ws, "doomed"), nil), http.StatusNoContent, "delete")
	b.janitorTick()
	if tags, err := reg.Tags(context.Background(), repo+"/cache"); err != nil || len(tags) != 0 {
		t.Fatalf("build cache survived the purge: %v %v", tags, err)
	}

	if b.count("SELECT count(*) FROM apps WHERE id = $1", appID) != 0 {
		t.Fatal("app row not purged")
	}
	if ok, err := registryClient(t).ManifestExists(context.Background(), repo, *d.ImageDigest); err != nil || ok {
		t.Fatalf("image survived the purge: %v %v", ok, err)
	}
	store := objects(t)
	for _, key := range []string{sourceKey, *logKey} {
		if _, err := store.Head(context.Background(), key); !errors.Is(err, objstore.ErrNotFound) {
			t.Fatalf("%s survived the purge: %v", key, err)
		}
	}
	// The slug is free again.
	b.createApp(b.alice, b.ws, "doomed")
}

func TestAbandonedUploadExpires(t *testing.T) {
	b := startQueueOnly(t, nil)
	b.createApp(b.alice, b.ws, "web")
	b.startDeploy(b.alice, b.ws, "web", project(t, helloDockerfile("never-uploaded")))
	b.exec("UPDATE deployments SET upload_expires_at = now() - interval '1 hour'")
	b.janitorTick()
	d := b.deployment(b.alice, b.ws, "web", 1)
	if d.Status != "failed" || d.FailureReason != "the source archive was not uploaded in time" {
		t.Fatalf("deployment %+v", d)
	}
}

// TestStrayImagesAreRemoved: an image pushed under a build tag that is not
// a deployment's recorded image (from an abandoned attempt) is deleted.
func TestStrayImagesAreRemoved(t *testing.T) {
	b := startBuildEnv(t, nil)
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("recorded")))
	d := b.waitStatus(b.alice, b.ws, "web", n, 3*time.Minute, "built")
	_, repo := b.appRepo(b.ws, "web")
	stray := pushTestImage(t, repo, "b-"+uuid.NewV7().String(), []byte("stray layer"))
	// The build cache of an app that does not exist (any more) goes too;
	// the live app's stays.
	strayCache := uuid.NewV7().String() + "/" + uuid.NewV7().String() + "/cache"
	pushTestImage(t, strayCache, apps.CacheTag, []byte("stray cache"))

	b.janitorTick()
	reg := registryClient(t)
	if ok, _ := reg.ManifestExists(context.Background(), repo, stray); ok {
		t.Fatal("stray image kept")
	}
	if ok, _ := reg.ManifestExists(context.Background(), repo, *d.ImageDigest); !ok {
		t.Fatal("recorded image removed")
	}
	if tags, err := reg.Tags(context.Background(), strayCache); err != nil || len(tags) != 0 {
		t.Fatalf("stray build cache kept: %v %v", tags, err)
	}
	if tags, err := reg.Tags(context.Background(), repo+"/cache"); err != nil || !slices.Contains(tags, apps.CacheTag) {
		t.Fatalf("the live app's build cache was removed: %v %v", tags, err)
	}
}

// pushTestImage pushes a one-layer image to the shared registry.
func pushTestImage(t *testing.T, repo, tag string, layer []byte) string {
	t.Helper()
	return pushImage(t, repo, tag, layer, nil)
}

// pushImage pushes a one-layer image whose config holds runConfig (the
// image's Cmd, User, ...) and returns the manifest digest.
func pushImage(t *testing.T, repo, tag string, layer []byte, runConfig map[string]any) string {
	t.Helper()
	ca, _, err := pki.LoadOrCreateCA(shared.caPath)
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.NewIssuer(ca, "nook", "nook-registry").Token("test", time.Minute, registry.RepositoryAccess(repo, registry.ActionPush, registry.ActionPull))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := testinfra.PushImage(context.Background(), shared.storage.Registry.Addr, ca.Pool(), token, repo, tag, layer, runConfig)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
