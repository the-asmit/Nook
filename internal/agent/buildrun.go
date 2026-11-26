package agent

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/archive"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Paths inside the build container (the BuildKit image's user is 1000,
// home /home/user).
const (
	buildUser       = "1000:1000"
	containerHome   = "/home/user"
	contextDir      = "ctx"
	metadataFile    = "out/metadata.json"
	downloadTimeout = 10 * time.Minute
)

// run performs one build and returns its result. It never returns
// secrets (the source URL, the registry token) in messages or logs.
func (b *builder) run(ctx context.Context, cmd *agentv1.BuildCommand) *agentv1.BuildFinished {
	id := cmd.GetBuildId()
	timeout := min(max(cmd.GetTimeout().AsDuration(), 5*time.Second), maxBuildTimeout)
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, context.DeadlineExceeded)
	defer cancel()
	logs := newLogStream(id, b.outbox, min(max(cmd.GetMaxLogBytes(), 64<<10), maxBuildLogBytes))
	defer logs.flush()
	logs.line(fmt.Sprintf("[nook] build %s (attempt %d) on node %s", id, cmd.GetAttempt(), b.nodeID()))

	dir := b.buildDir(id)
	if err := os.MkdirAll(filepath.Join(dir, contextDir), 0o700); err != nil {
		return infraError(id, "could not create the build directory")
	}
	defer func() { _ = os.RemoveAll(dir) }()

	logs.line(fmt.Sprintf("[nook] downloading source (%d bytes)", cmd.GetSourceSize()))
	archivePath := filepath.Join(dir, "source.tar.gz")
	if err := download(ctx, cmd, archivePath); err != nil {
		if r := stopped(ctx, id, logs); r != nil {
			return r
		}
		b.logger.Warn("source download failed", "build_id", id, "error", err.Error())
		return withLog(infraError(id, "downloading the source failed"), logs)
	}
	if err := extract(archivePath, filepath.Join(dir, contextDir), b.cfg.BuildMaxContextBytes); err != nil {
		logs.line("[nook] " + err.Error())
		return withLog(result(id, agentv1.BuildResult_BUILD_RESULT_FAILED, "the source archive is invalid: "+err.Error()), logs)
	}
	if info, err := os.Lstat(filepath.Join(dir, contextDir, "Dockerfile")); err != nil || !info.Mode().IsRegular() {
		logs.line("[nook] no Dockerfile at the root of the project")
		return withLog(result(id, agentv1.BuildResult_BUILD_RESULT_FAILED, "there is no Dockerfile at the root of the project"), logs)
	}
	if r := stopped(ctx, id, logs); r != nil {
		return r
	}
	if err := b.docker.ensureImage(ctx, b.cfg.BuildImage); err != nil {
		b.logger.Warn("could not pull the BuildKit image", "error", err.Error())
		return withLog(infraError(id, "the node could not prepare the builder"), logs)
	}
	return b.runContainer(ctx, cmd, dir, logs)
}

// runContainer runs BuildKit in a fresh container and waits for it.
func (b *builder) runContainer(ctx context.Context, cmd *agentv1.BuildCommand, dir string, logs *logStream) *agentv1.BuildFinished {
	id := cmd.GetBuildId()
	// Docker calls use their own context: cleanup must happen even after
	// the build's context was canceled.
	dockerCtx := context.WithoutCancel(ctx)
	if err := b.docker.ensureBuildNetwork(dockerCtx, b.cfg.BuildNetwork); err != nil {
		b.logger.Warn("could not create the build network", "build_id", id, "error", err.Error())
		return withLog(infraError(id, "the node could not prepare the build network"), logs)
	}
	var proxy proxyConfig
	if b.cfg.BuildProxy {
		proxy = b.docker.proxy(dockerCtx)
	}
	created, err := b.docker.client.ContainerCreate(dockerCtx, b.containerSpec(cmd, proxy))
	if err != nil {
		b.logger.Warn("could not create the build container", "build_id", id, "error", err.Error())
		return withLog(infraError(id, "the node could not start the build"), logs)
	}
	defer func() {
		rmCtx, cancel := context.WithTimeout(dockerCtx, time.Minute)
		defer cancel()
		if _, rmErr := b.docker.client.ContainerRemove(rmCtx, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); rmErr != nil {
			b.logger.Warn("could not remove the build container", "build_id", id, "error", rmErr.Error())
		}
	}()

	var resolvers []netip.Addr
	if b.resolvers != nil {
		resolvers = b.resolvers()
	}
	content := containerFiles(filepath.Join(dir, contextDir), cmd, b.caPEM(), resolvers)
	_, err = b.docker.client.CopyToContainer(dockerCtx, created.ID, client.CopyToContainerOptions{DestinationPath: containerHome, Content: content})
	_ = content.Close()
	if err != nil {
		b.logger.Warn("could not copy the build context", "build_id", id, "error", err.Error())
		return withLog(infraError(id, "the node could not prepare the build"), logs)
	}
	if _, err := b.docker.client.ContainerStart(dockerCtx, created.ID, client.ContainerStartOptions{}); err != nil {
		b.logger.Warn("could not start the build container", "build_id", id, "error", err.Error())
		return withLog(infraError(id, "the node could not start the build"), logs)
	}
	logs.line("[nook] building with BuildKit")
	logsDone := make(chan struct{})
	go func() {
		defer close(logsDone)
		b.followLogs(dockerCtx, created.ID, logs)
	}()

	wait := b.docker.client.ContainerWait(dockerCtx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	var exitCode int64
	select {
	case res := <-wait.Result:
		exitCode = res.StatusCode
	case err := <-wait.Error:
		b.logger.Warn("waiting for the build container failed", "build_id", id, "error", err.Error())
		return withLog(infraError(id, "the node lost track of the build"), logs)
	case <-ctx.Done():
		killCtx, cancel := context.WithTimeout(dockerCtx, 30*time.Second)
		_, _ = b.docker.client.ContainerKill(killCtx, created.ID, client.ContainerKillOptions{})
		cancel()
		<-logsDone
		return stopped(ctx, id, logs)
	}
	<-logsDone
	if exitCode == 0 {
		digest, err := b.imageDigest(dockerCtx, created.ID)
		if err != nil {
			b.logger.Warn("build produced no image digest", "build_id", id, "error", err.Error())
			return withLog(infraError(id, "the build did not report the pushed image"), logs)
		}
		logs.line("[nook] pushed " + cmd.GetRegistry() + "/" + cmd.GetRepository() + "@" + digest)
		r := withLog(result(id, agentv1.BuildResult_BUILD_RESULT_SUCCEEDED, "built and pushed"), logs)
		r.ImageDigest = digest
		return r
	}
	return b.failure(dockerCtx, created.ID, cmd, logs, exitCode)
}

// failure classifies a non-zero exit: the user's build failed, unless the
// container ran out of memory (also the user's build) or the error was in
// pushing to Nook's registry (infrastructure, retried elsewhere).
func (b *builder) failure(ctx context.Context, containerID string, cmd *agentv1.BuildCommand, logs *logStream, exitCode int64) *agentv1.BuildFinished {
	id := cmd.GetBuildId()
	inspectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if info, err := b.docker.client.ContainerInspect(inspectCtx, containerID, client.ContainerInspectOptions{}); err == nil &&
		info.Container.State != nil && info.Container.State.OOMKilled {
		msg := "the build ran out of memory (limit " + strconv.FormatInt(cmd.GetMemoryBytes()>>20, 10) + " MiB)"
		logs.line("[nook] " + msg)
		return withLog(result(id, agentv1.BuildResult_BUILD_RESULT_FAILED, msg), logs)
	}
	if logs.mentionsAfterError(cmd.GetRegistry()) {
		logs.line("[nook] pushing to the Nook registry failed; the build will be retried")
		return withLog(infraError(id, "pushing the image to the registry failed"), logs)
	}
	logs.line("[nook] the build failed (exit code " + strconv.FormatInt(exitCode, 10) + ")")
	return withLog(result(id, agentv1.BuildResult_BUILD_RESULT_FAILED, "the build failed; see the build log"), logs)
}

// stopped returns the result for a build whose context ended, or nil if
// it is still live.
func stopped(ctx context.Context, id string, logs *logStream) *agentv1.BuildFinished {
	if ctx.Err() == nil {
		return nil
	}
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errCanceled):
		logs.line("[nook] build canceled")
		return withLog(result(id, agentv1.BuildResult_BUILD_RESULT_CANCELED, "canceled"), logs)
	case errors.Is(cause, errShuttingDown):
		logs.line("[nook] the agent is shutting down; the build will be retried on another node")
		return withLog(infraError(id, "the node's agent shut down during the build"), logs)
	default:
		logs.line("[nook] the build exceeded its time limit and was stopped")
		return withLog(result(id, agentv1.BuildResult_BUILD_RESULT_TIMED_OUT, "the build exceeded its time limit"), logs)
	}
}

func withLog(r *agentv1.BuildFinished, logs *logStream) *agentv1.BuildFinished {
	logs.flush()
	r.LogBytes = logs.total()
	return r
}

// containerSpec is the build container: BuildKit, rootless, in a user
// namespace of its own, with every capability dropped except the two that
// map that namespace, no host mounts, no Docker socket and hard limits.
// Its seccomp profile is Docker's default plus the system calls that
// creating the user namespace needs (see the build-isolation ADR).
func (b *builder) containerSpec(cmd *agentv1.BuildCommand, proxy proxyConfig) client.ContainerCreateOptions {
	// Validated at startup.
	pairs, _ := parseBuildHosts(b.cfg.BuildHosts)
	hosts := buildHosts(pairs)
	ref := cmd.GetRegistry() + "/" + cmd.GetRepository() + ":" + cmd.GetTag()
	memory := min(max(cmd.GetMemoryBytes(), minBuildMemory), maxBuildMemory)
	millicores := min(max(cmd.GetCpuMillicores(), 100), maxBuildMillicore)
	pids := int64(buildPIDsLimit)
	return client.ContainerCreateOptions{
		Name: "nook-build-" + cmd.GetBuildId(),
		Config: &container.Config{
			Image:      b.cfg.BuildImage,
			User:       buildUser,
			Entrypoint: []string{"buildctl-daemonless.sh"},
			Cmd: append([]string{
				"build", "--frontend", "dockerfile.v0",
				"--local", "context=" + containerHome + "/" + contextDir,
				"--local", "dockerfile=" + containerHome + "/" + contextDir,
				"--output", "type=image,name=" + ref + ",push=true",
				"--metadata-file", containerHome + "/" + metadataFile,
				"--progress", "plain",
			}, append(proxy.buildArgs(), hosts.buildOpts()...)...),
			Env: append([]string{
				"BUILDKITD_FLAGS=--config=" + containerHome + "/.config/buildkit/buildkitd.toml",
				"DOCKER_CONFIG=" + containerHome + "/.docker",
			}, proxy.env(registryHost(cmd.GetRegistry()))...),
			Labels: map[string]string{buildLabel: cmd.GetBuildId(), buildNodeLabel: b.nodeID()},
		},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(b.cfg.BuildNetwork),
			ExtraHosts:  hosts.extraHosts(),
			CapDrop:     []string{"ALL"},
			CapAdd:      []string{"SETUID", "SETGID"},
			SecurityOpt: []string{"seccomp=" + buildSeccompProfile},
			Resources: container.Resources{
				Memory: memory, MemorySwap: memory, NanoCPUs: millicores * 1_000_000, PidsLimit: &pids,
			},
		},
	}
}

func (b *builder) imageDigest(ctx context.Context, containerID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := b.docker.client.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{SourcePath: containerHome + "/" + metadataFile})
	if err != nil {
		return "", fmt.Errorf("copy metadata: %w", err)
	}
	defer func() { _ = res.Content.Close() }()
	tr := tar.NewReader(res.Content)
	if _, err := tr.Next(); err != nil {
		return "", fmt.Errorf("read metadata archive: %w", err)
	}
	var meta map[string]any
	if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&meta); err != nil {
		return "", fmt.Errorf("decode metadata: %w", err)
	}
	digest, _ := meta["containerimage.digest"].(string)
	if !strings.HasPrefix(digest, "sha256:") || !sha256Pattern.MatchString(strings.TrimPrefix(digest, "sha256:")) {
		return "", errors.New("metadata has no image digest")
	}
	return digest, nil
}

func (b *builder) followLogs(ctx context.Context, containerID string, logs *logStream) {
	rc, err := b.docker.client.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Follow: true})
	if err != nil {
		logs.line("[nook] build output is unavailable")
		return
	}
	defer func() { _ = rc.Close() }()
	_, _ = stdcopy.StdCopy(logs, logs, rc)
	logs.flushPartial()
}

// download fetches the source archive and verifies its size and SHA-256.
func download(ctx context.Context, cmd *agentv1.BuildCommand, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cmd.GetSourceUrl(), http.NoBody)
	if err != nil {
		return errors.New("invalid source URL")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// url.Error embeds the presigned URL, which is a credential.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("download source: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download source: HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a path inside the agent's own build directory.
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, cmd.GetSourceSize()+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("download source: %w", err)
	}
	if n != cmd.GetSourceSize() || hex.EncodeToString(h.Sum(nil)) != cmd.GetSourceSha256() {
		return errors.New("downloaded source does not match the expected size and checksum")
	}
	return nil
}

func extract(archivePath, dest string, maxBytes int64) error {
	f, err := os.Open(archivePath) //nolint:gosec // G304: a path inside the agent's own build directory.
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = f.Close() }()
	return archive.Extract(f, dest, archive.Limits{MaxBytes: maxBytes, MaxEntries: 200_000})
}

// buildHosts are extra host entries for the build container (BuildKit
// pulling base images, pushing) and its RUN steps.
type buildHosts [][2]string

// extraHosts is the container's /etc/hosts additions.
func (h buildHosts) extraHosts() []string {
	out := make([]string, 0, len(h))
	for _, p := range h {
		out = append(out, p[0]+":"+p[1])
	}
	return out
}

// buildOpts adds the same entries to RUN steps.
func (h buildHosts) buildOpts() []string {
	if len(h) == 0 {
		return nil
	}
	parts := make([]string, 0, len(h))
	for _, p := range h {
		parts = append(parts, p[0]+"="+p[1])
	}
	return []string{"--opt", "add-hosts=" + strings.Join(parts, ",")}
}
