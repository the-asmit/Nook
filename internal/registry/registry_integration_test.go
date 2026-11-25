//go:build integration

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/testinfra"
)

type fixture struct {
	ca       *pki.CA
	storage  *testinfra.StorageT
	issuer   *Issuer
	client   *Client
	http     *http.Client
	base     string
	contents map[string][]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	ca, _, err := pki.LoadOrCreateCA(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCertificate([]string{"registry", "localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(dir, "registry")
	if err := ca.WriteServerFiles(certDir, cert); err != nil {
		t.Fatal(err)
	}
	s := testinfra.MustStorage(t, certDir)
	issuer := NewIssuer(ca, "nook", "nook-registry")
	cfg := &Config{Addr: s.Registry.Addr, Service: "nook-registry", Issuer: "nook", RequestTimeout: 10 * time.Second}
	return &fixture{
		ca: ca, storage: s, issuer: issuer, client: NewClient(cfg, issuer, ca), base: cfg.BaseURL(),
		http:     &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca.Pool()}}},
		contents: map[string][]byte{},
	}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// result is what the tests need of a response (its body is already closed).
type result struct {
	StatusCode int
	Header     http.Header
}

func (f *fixture) call(t *testing.T, token, method, path, contentType string, body []byte) result {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", manifestTypes)
	resp, err := f.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header}
}

// pushBlob uploads a blob (start an upload session, then complete it in
// one PUT) and reports the HTTP status of the first failing step.
func (f *fixture) pushBlob(t *testing.T, token, repo string, data []byte) int {
	t.Helper()
	start := f.call(t, token, http.MethodPost, fmt.Sprintf("/v2/%s/blobs/uploads/", repo), "", nil)
	if start.StatusCode != http.StatusAccepted {
		return start.StatusCode
	}
	loc, err := url.Parse(start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	q.Set("digest", digestOf(data))
	loc.RawQuery = q.Encode()
	return f.call(t, token, http.MethodPut, loc.RequestURI(), "application/octet-stream", data).StatusCode
}

// pushImage pushes a one-layer OCI image and returns its manifest digest.
func (f *fixture) pushImage(t *testing.T, token, repo, tag string, layer []byte) string {
	t.Helper()
	cfg := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["` + digestOf(layer) + `"]}}`)
	for _, b := range [][]byte{cfg, layer} {
		if code := f.pushBlob(t, token, repo, b); code != http.StatusCreated {
			t.Fatalf("push blob: HTTP %d", code)
		}
	}
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestOf(cfg), "size": len(cfg)},
		"layers":        []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digestOf(layer), "size": len(layer)}},
	})
	resp := f.call(t, token, http.MethodPut, "/v2/"+repo+"/manifests/"+tag, "application/vnd.oci.image.manifest.v1+json", manifest)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push manifest: HTTP %d", resp.StatusCode)
	}
	return digestOf(manifest)
}

func TestTokenAuthentication(t *testing.T) {
	f := newFixture(t)
	repo := "ws1/app1"
	push, err := f.issuer.Token("node-a", time.Minute, RepositoryAccess(repo, ActionPush, ActionPull))
	if err != nil {
		t.Fatal(err)
	}
	digest := f.pushImage(t, push, repo, "b-1", []byte("layer one"))

	otherRepo, _ := f.issuer.Token("node-a", time.Minute, RepositoryAccess("ws2/app9", ActionPush, ActionPull))
	pullOnly, _ := f.issuer.Token("node-a", time.Minute, RepositoryAccess(repo, ActionPull))
	expired, _ := func() (string, error) {
		f.issuer.now = func() time.Time { return time.Now().Add(-time.Hour) }
		defer func() { f.issuer.now = time.Now }()
		return f.issuer.Token("node-a", time.Minute, RepositoryAccess(repo, ActionPush, ActionPull))
	}()
	foreignCA, _, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "other.pem"))
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := NewIssuer(foreignCA, "nook", "nook-registry").Token("node-a", time.Minute, RepositoryAccess(repo, ActionPush, ActionPull))

	manifestPath := "/v2/" + repo + "/manifests/" + digest
	cases := []struct {
		name  string
		token string
		push  int
		pull  int
	}{
		{"no token", "", http.StatusUnauthorized, http.StatusUnauthorized},
		{"token for another repository", otherRepo, http.StatusUnauthorized, http.StatusUnauthorized},
		{"expired token", expired, http.StatusUnauthorized, http.StatusUnauthorized},
		{"token signed by another CA", forged, http.StatusUnauthorized, http.StatusUnauthorized},
		{"pull-only token", pullOnly, http.StatusUnauthorized, http.StatusOK},
		{"push token", push, http.StatusCreated, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.pushBlob(t, tc.token, repo, []byte("blob for "+tc.name)); got != tc.push {
				t.Errorf("push: HTTP %d, want %d", got, tc.push)
			}
			if got := f.call(t, tc.token, http.MethodGet, manifestPath, "", nil).StatusCode; got != tc.pull {
				t.Errorf("pull: HTTP %d, want %d", got, tc.pull)
			}
		})
	}
}

func TestDeleteAndGarbageCollect(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	repo := "ws1/app1"
	push, _ := f.issuer.Token("node-a", time.Minute, RepositoryAccess(repo, ActionPush, ActionPull))
	keepLayer, dropLayer := []byte("layer kept"), []byte("layer dropped")
	keep := f.pushImage(t, push, repo, "b-keep", keepLayer)
	drop := f.pushImage(t, push, repo, "b-drop", dropLayer)

	if d, err := f.client.TagDigest(ctx, repo, "b-drop"); err != nil || d != drop {
		t.Fatalf("tag digest %s %v", d, err)
	}
	tags, err := f.client.Tags(ctx, repo)
	if err != nil || !slices.Equal(tags, []string{"b-drop", "b-keep"}) {
		t.Fatalf("tags %v %v", tags, err)
	}
	repos, err := f.client.Repositories(ctx)
	if err != nil || !slices.Contains(repos, repo) {
		t.Fatalf("catalog %v %v", repos, err)
	}

	if err := f.client.DeleteManifest(ctx, repo, drop); err != nil {
		t.Fatal(err)
	}
	if err := f.client.DeleteManifest(ctx, repo, drop); err != nil {
		t.Fatalf("deleting twice: %v", err)
	}
	if ok, err := f.client.ManifestExists(ctx, repo, drop); err != nil || ok {
		t.Fatalf("deleted manifest still exists: %v %v", ok, err)
	}
	if out, err := f.storage.Registry.GarbageCollect(ctx); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pull, _ := f.issuer.Token("node-a", time.Minute, RepositoryAccess(repo, ActionPull))
	if code := f.call(t, pull, http.MethodHead, "/v2/"+repo+"/blobs/"+digestOf(dropLayer), "", nil).StatusCode; code != http.StatusNotFound {
		t.Fatalf("dropped layer after GC: HTTP %d", code)
	}
	if code := f.call(t, pull, http.MethodHead, "/v2/"+repo+"/blobs/"+digestOf(keepLayer), "", nil).StatusCode; code != http.StatusOK {
		t.Fatalf("kept layer after GC: HTTP %d", code)
	}
	if ok, err := f.client.ManifestExists(ctx, repo, keep); err != nil || !ok {
		t.Fatalf("kept image gone: %v %v", ok, err)
	}
}
