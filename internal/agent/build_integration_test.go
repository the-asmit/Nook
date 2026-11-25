//go:build integration

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/the-asmit/nook/internal/archive"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/testinfra"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

type buildFixture struct {
	t        *testing.T
	ca       *pki.CA
	storage  *testinfra.StorageT
	objects  *objstore.Client
	issuer   *registry.Issuer
	registry *registry.Client
	builder  *builder
	outbox   *outbox
}

func newBuildFixture(t *testing.T) *buildFixture {
	t.Helper()
	dir := t.TempDir()
	ca, _, err := pki.LoadOrCreateCA(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCertificate([]string{testinfra.RegistryAlias, "localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = ca.WriteServerFiles(filepath.Join(dir, "registry"), cert); err != nil {
		t.Fatal(err)
	}
	s := testinfra.MustStorage(t, filepath.Join(dir, "registry"), "nook-test")
	objects, err := objstore.New(&objstore.Config{Endpoint: s.MinIO.URL, Region: "us-east-1", Bucket: "nook-test",
		AccessKeyID: s.MinIO.AccessKey, SecretAccessKey: config.NewSecret(s.MinIO.SecretKey), RequestTimeout: 30 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load[Config](map[string]string{
		"NOOK_AGENT_STATE_DIR": filepath.Join(dir, "agent"), "NOOK_AGENT_BUILD_NETWORK": s.Network.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := newDocker()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	out := newOutbox()
	nodeID := uuid.NewV7().String()
	b := newBuilder(&cfg, d, out, slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return nodeID }, ca.CertificatePEM)
	t.Cleanup(b.stop)
	issuer := registry.NewIssuer(ca, "nook", "nook-registry")
	regCfg := &registry.Config{Addr: s.Registry.Addr, Service: "nook-registry", Issuer: "nook", RequestTimeout: 30 * time.Second}
	return &buildFixture{t: t, ca: ca, storage: s, objects: objects, issuer: issuer, registry: registry.NewClient(regCfg, issuer, ca), builder: b, outbox: out}
}

// command packs files (a project), uploads the archive and returns a
// build command for it.
func (f *buildFixture) command(files map[string]string, timeout time.Duration) *agentv1.BuildCommand {
	f.t.Helper()
	dir := f.t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			f.t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	res, err := archive.Pack(dir, &buf, archive.PackOptions{})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.commandFor(buf.Bytes(), res.SHA256, "ws1/app1", timeout)
}

func (f *buildFixture) commandFor(data, sum []byte, repo string, timeout time.Duration) *agentv1.BuildCommand {
	f.t.Helper()
	id := uuid.NewV7().String()
	key := "sources/" + id + ".tar.gz"
	up := f.objects.PresignPut(key, int64(len(data)), sum, time.Minute)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, up.URL, bytes.NewReader(data))
	for k, v := range up.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		f.t.Fatalf("upload source: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	token, err := f.issuer.Token("test-node", time.Hour, registry.RepositoryAccess(repo, registry.ActionPush, registry.ActionPull))
	if err != nil {
		f.t.Fatal(err)
	}
	return &agentv1.BuildCommand{
		BuildId: id, DeploymentId: uuid.NewV7().String(), Attempt: 1,
		SourceUrl: f.objects.PresignGet(key, time.Hour), SourceSha256: hex.EncodeToString(sum), SourceSize: int64(len(data)),
		Registry: f.storage.Registry.NetworkAddr, Repository: repo, Tag: "b-" + id, RegistryToken: token,
		Timeout: durationpb.New(timeout), MemoryBytes: 1 << 30, CpuMillicores: 2000, MaxLogBytes: 1 << 20,
	}
}

// await collects log lines until the build finishes.
func (f *buildFixture) await(id string, within time.Duration) (*agentv1.BuildFinished, []string) {
	f.t.Helper()
	var lines []string
	deadline := time.After(within)
	for {
		for _, m := range f.outbox.take() {
			if l := m.GetBuildLog(); l != nil && l.GetBuildId() == id {
				lines = append(lines, l.GetLines()...)
			}
			if r := m.GetBuildFinished(); r != nil && r.GetBuildId() == id {
				return r, lines
			}
		}
		select {
		case <-f.outbox.ready:
		case <-deadline:
			f.t.Fatalf("build %s did not finish; log:\n%s", id, strings.Join(lines, "\n"))
		}
	}
}

func TestBuildPushesToTheRegistry(t *testing.T) {
	f := newBuildFixture(t)
	cmd := f.command(map[string]string{
		"Dockerfile": "FROM alpine:3.23\nCOPY hello.txt /hello.txt\nRUN cat /hello.txt && id\n",
		"hello.txt":  "hello from nook\n",
	}, 5*time.Minute)
	if err := f.builder.start(cmd); err != nil {
		t.Fatal(err)
	}
	res, lines := f.await(cmd.GetBuildId(), 5*time.Minute)
	log := strings.Join(lines, "\n")
	if res.GetResult() != agentv1.BuildResult_BUILD_RESULT_SUCCEEDED {
		t.Fatalf("result %v (%s); log:\n%s", res.GetResult(), res.GetMessage(), log)
	}
	if !strings.Contains(log, "hello from nook") || strings.Contains(log, cmd.GetRegistryToken()) || strings.Contains(log, "X-Amz-Signature") {
		t.Fatalf("unexpected log:\n%s", log)
	}
	ok, err := f.registry.ManifestExists(context.Background(), "ws1/app1", res.GetImageDigest())
	if err != nil || !ok {
		t.Fatalf("image %s not in the registry: %v", res.GetImageDigest(), err)
	}
	if d, err := f.registry.TagDigest(context.Background(), "ws1/app1", cmd.GetTag()); err != nil || d != res.GetImageDigest() {
		t.Fatalf("tag points to %s (%v), want %s", d, err, res.GetImageDigest())
	}
	if _, err := os.Stat(f.builder.buildDir(cmd.GetBuildId())); !os.IsNotExist(err) {
		t.Fatalf("build directory left behind: %v", err)
	}
}

func TestFailingDockerfile(t *testing.T) {
	f := newBuildFixture(t)
	cmd := f.command(map[string]string{"Dockerfile": "FROM alpine:3.23\nRUN echo about to fail && exit 3\n"}, 5*time.Minute)
	if err := f.builder.start(cmd); err != nil {
		t.Fatal(err)
	}
	res, lines := f.await(cmd.GetBuildId(), 5*time.Minute)
	log := strings.Join(lines, "\n")
	if res.GetResult() != agentv1.BuildResult_BUILD_RESULT_FAILED || !strings.Contains(log, "about to fail") || !strings.Contains(log, "exit code: 3") {
		t.Fatalf("result %v (%s); log:\n%s", res.GetResult(), res.GetMessage(), log)
	}
}

func TestBuildTimeLimit(t *testing.T) {
	f := newBuildFixture(t)
	cmd := f.command(map[string]string{"Dockerfile": "FROM alpine:3.23\nRUN sleep 600\n"}, 20*time.Second)
	start := time.Now()
	if err := f.builder.start(cmd); err != nil {
		t.Fatal(err)
	}
	res, _ := f.await(cmd.GetBuildId(), 3*time.Minute)
	if res.GetResult() != agentv1.BuildResult_BUILD_RESULT_TIMED_OUT {
		t.Fatalf("result %v (%s)", res.GetResult(), res.GetMessage())
	}
	if took := time.Since(start); took > 2*time.Minute {
		t.Fatalf("killing the build took %s", took)
	}
}

func TestCancelRunningBuild(t *testing.T) {
	f := newBuildFixture(t)
	cmd := f.command(map[string]string{"Dockerfile": "FROM alpine:3.23\nRUN echo started && sleep 600\n"}, 10*time.Minute)
	if err := f.builder.start(cmd); err != nil {
		t.Fatal(err)
	}
	// Wait until the build is actually running.
	var lines []string
	deadline := time.Now().Add(3 * time.Minute)
	for !strings.Contains(strings.Join(lines, "\n"), "started") {
		if time.Now().After(deadline) {
			t.Fatalf("build never started:\n%s", strings.Join(lines, "\n"))
		}
		for _, m := range f.outbox.take() {
			lines = append(lines, m.GetBuildLog().GetLines()...)
		}
		select {
		case <-f.outbox.ready:
		case <-time.After(time.Second):
		}
	}
	if !f.builder.cancelBuild(cmd.GetBuildId()) {
		t.Fatal("build not running")
	}
	res, _ := f.await(cmd.GetBuildId(), 2*time.Minute)
	if res.GetResult() != agentv1.BuildResult_BUILD_RESULT_CANCELED {
		t.Fatalf("result %v (%s)", res.GetResult(), res.GetMessage())
	}
}

func TestPushWithTokenForAnotherRepositoryIsAnInfraError(t *testing.T) {
	f := newBuildFixture(t)
	cmd := f.command(map[string]string{"Dockerfile": "FROM alpine:3.23\nRUN true\n"}, 5*time.Minute)
	cmd.RegistryToken, _ = f.issuer.Token("test-node", time.Hour, registry.RepositoryAccess("ws2/other", registry.ActionPush, registry.ActionPull))
	if err := f.builder.start(cmd); err != nil {
		t.Fatal(err)
	}
	res, lines := f.await(cmd.GetBuildId(), 5*time.Minute)
	if res.GetResult() != agentv1.BuildResult_BUILD_RESULT_INFRA_ERROR {
		t.Fatalf("result %v (%s); log:\n%s", res.GetResult(), res.GetMessage(), strings.Join(lines, "\n"))
	}
	if ok, _ := f.registry.ManifestExists(context.Background(), "ws1/app1", "sha256:"+strings.Repeat("0", 64)); ok {
		t.Fatal("unexpected manifest")
	}
}

func TestMaliciousArchiveIsRejected(t *testing.T) {
	f := newBuildFixture(t)
	data := maliciousArchive(t)
	sum := sha256.Sum256(data)
	cmd := f.commandFor(data, sum[:], "ws1/app1", time.Minute)
	if err := f.builder.start(cmd); err != nil {
		t.Fatal(err)
	}
	res, _ := f.await(cmd.GetBuildId(), time.Minute)
	if res.GetResult() != agentv1.BuildResult_BUILD_RESULT_FAILED || !strings.Contains(res.GetMessage(), "invalid") {
		t.Fatalf("result %v (%s)", res.GetResult(), res.GetMessage())
	}
}

func TestBusyAndValidation(t *testing.T) {
	cfg, err := config.Load[Config](map[string]string{"NOOK_AGENT_BUILD_SLOTS": "0"})
	if err != nil {
		t.Fatal(err)
	}
	b := newBuilder(&cfg, nil, newOutbox(), slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return "n" }, nil)
	cmd := &agentv1.BuildCommand{
		BuildId: uuid.NewV7().String(), SourceUrl: "https://s3/x", SourceSha256: strings.Repeat("a", 64), SourceSize: 1,
		Registry: "registry:5000", Repository: "ws/app", Tag: "b-1", RegistryToken: "t",
	}
	if err := b.start(cmd); !errors.Is(err, errBusy) {
		t.Fatalf("no slots: %v", err)
	}
	bad, _ := proto.Clone(cmd).(*agentv1.BuildCommand)
	bad.Registry = `evil"]` + "\n[x]"
	if err := b.start(bad); err == nil || errors.Is(err, errBusy) {
		t.Fatalf("injected registry accepted: %v", err)
	}
}

// maliciousArchive tries to write outside the build directory.
func maliciousArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range []*tar.Header{
		{Name: "Dockerfile", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5},
		{Name: "../../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte("hello"))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}
