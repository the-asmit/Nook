package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// ManagedLabel marks containers that Nook created and manages.
const ManagedLabel = "nook.managed"

// maxListedContainers keeps inspection results well under the gRPC
// message size limit.
const maxListedContainers = 500

// dockerTimeout bounds each call to the Docker engine.
const dockerTimeout = 10 * time.Second

// docker talks to the local Docker engine through its Engine API.
type docker struct {
	client *client.Client
}

// newDocker connects using the standard DOCKER_HOST/DOCKER_* environment
// (default: the local Unix socket) and negotiates the API version, so the
// agent works with any supported engine version.
func newDocker() (*docker, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("configure docker client: %w", err)
	}
	return &docker{client: c}, nil
}

func (d *docker) close() error { return d.client.Close() }

// unreachable wraps an engine error with advice the operator can act on.
func unreachable(err error) error {
	return fmt.Errorf("docker engine unreachable (is Docker running, and may the agent use its socket?): %w", err)
}

// version returns the engine version, or an error if it is unreachable.
func (d *docker) version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	v, err := d.client.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return "", unreachable(err)
	}
	return v.Version, nil
}

// runningContainers counts running containers on the node.
func (d *docker) runningContainers(ctx context.Context) (int32, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := d.client.Info(ctx, client.InfoOptions{})
	if err != nil {
		return 0, unreachable(err)
	}
	return int32(min(info.Info.ContainersRunning, 1<<31-1)), nil //nolint:gosec // G115: clamped above.
}

// inspect gathers live engine information and Nook-managed containers.
func (d *docker) inspect(ctx context.Context) (*agentv1.InspectNodeResult, error) {
	info, err := d.client.Info(ctx, client.InfoOptions{})
	if err != nil {
		return nil, unreachable(err)
	}
	ver, err := d.client.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return nil, unreachable(err)
	}
	list, err := d.client.ContainerList(ctx, client.ContainerListOptions{
		All: true, Limit: maxListedContainers, Filters: client.Filters{}.Add("label", ManagedLabel+"=true"),
	})
	if err != nil {
		return nil, unreachable(err)
	}
	i := info.Info
	res := &agentv1.InspectNodeResult{Docker: &agentv1.DockerInfo{
		ServerVersion: i.ServerVersion, ApiVersion: ver.APIVersion, OperatingSystem: i.OperatingSystem,
		KernelVersion: i.KernelVersion, Architecture: i.Architecture, Cpus: clamp32(i.NCPU),
		MemoryTotalBytes: i.MemTotal, StorageDriver: i.Driver, ContainersRunning: clamp32(i.ContainersRunning),
		ContainersTotal: clamp32(i.Containers), Images: clamp32(i.Images),
	}}
	for i := range list.Items {
		c := &list.Items[i]
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		res.Containers = append(res.Containers, &agentv1.ManagedContainer{
			Id: c.ID, Name: name, Image: c.Image, State: string(c.State), Status: c.Status,
			Labels: c.Labels, CreatedAt: timestamppb.New(time.Unix(c.Created, 0)),
		})
	}
	return res, nil
}

// rootDir returns the engine's data directory, used for disk statistics.
func (d *docker) rootDir(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := d.client.Info(ctx, client.InfoOptions{})
	if err != nil || info.Info.DockerRootDir == "" {
		return "/"
	}
	return info.Info.DockerRootDir
}

func clamp32(n int) int32 {
	return int32(max(min(n, 1<<31-1), 0))
}

// imagePullTimeout bounds pulling the BuildKit image on first use.
const imagePullTimeout = 10 * time.Minute

// ensureImage pulls ref unless the engine already has it.
func (d *docker) ensureImage(ctx context.Context, ref string) error {
	inspectCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
	_, err := d.client.ImageInspect(inspectCtx, ref)
	cancel()
	if err == nil {
		return nil
	}
	ctx, cancel = context.WithTimeout(ctx, imagePullTimeout)
	defer cancel()
	resp, err := d.client.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer func() { _ = resp.Close() }()
	if err := resp.Wait(ctx); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

// runOnce runs a short-lived container to completion and returns its exit
// code and combined output (at most 64 KiB). The container is removed.
func (d *docker) runOnce(ctx context.Context, spec client.ContainerCreateOptions) (int64, string, error) {
	created, err := d.client.ContainerCreate(ctx, spec)
	if err != nil {
		return 0, "", fmt.Errorf("create helper container: %w", err)
	}
	defer func() {
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		_, _ = d.client.ContainerRemove(rmCtx, created.ID, client.ContainerRemoveOptions{Force: true})
	}()
	wait := d.client.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	if _, startErr := d.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); startErr != nil {
		return 0, "", fmt.Errorf("start helper container: %w", startErr)
	}
	var code int64
	select {
	case res := <-wait.Result:
		code = res.StatusCode
	case waitErr := <-wait.Error:
		return 0, "", fmt.Errorf("wait for helper container: %w", waitErr)
	}
	rc, err := d.client.ContainerLogs(ctx, created.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return code, "", nil
	}
	defer func() { _ = rc.Close() }()
	var sb strings.Builder
	_, _ = stdcopy.StdCopy(&sb, &sb, io.LimitReader(rc, 64<<10))
	return code, sb.String(), nil
}

// proxyConfig is the HTTP proxy the Docker engine is configured with.
type proxyConfig struct {
	HTTP, HTTPS, NoProxy string
}

// proxy returns the engine's proxy configuration (empty if none or if the
// engine is unreachable). Builds use it to reach base images when the
// node only has internet access through a proxy.
func (d *docker) proxy(ctx context.Context) proxyConfig {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := d.client.Info(ctx, client.InfoOptions{})
	if err != nil {
		return proxyConfig{}
	}
	return proxyConfig{HTTP: info.Info.HTTPProxy, HTTPS: info.Info.HTTPSProxy, NoProxy: info.Info.NoProxy}
}

func (p proxyConfig) empty() bool { return p.HTTP == "" && p.HTTPS == "" }

// withScheme makes "host:port" a URL, as programs expect in *_PROXY.
func withScheme(s string) string {
	if s == "" || strings.Contains(s, "://") {
		return s
	}
	return "http://" + s
}

// noProxy is the engine's exclusions plus the registry (pushes go to it
// directly) and loopback.
func (p proxyConfig) noProxy(registry string) string {
	list := []string{"localhost", "127.0.0.1"}
	if registry != "" {
		list = append(list, registry)
	}
	if p.NoProxy != "" {
		list = append(list, p.NoProxy)
	}
	return strings.Join(list, ",")
}

// env is the proxy environment for BuildKit itself (pulling base images).
func (p proxyConfig) env(registry string) []string {
	if p.empty() {
		return nil
	}
	h, s, n := withScheme(p.HTTP), withScheme(p.HTTPS), p.noProxy(registry)
	return []string{"HTTP_PROXY=" + h, "http_proxy=" + h, "HTTPS_PROXY=" + s, "https_proxy=" + s, "NO_PROXY=" + n, "no_proxy=" + n}
}

// buildArgs passes the proxy to RUN steps (BuildKit's predefined proxy
// build arguments, which do not end up in the image).
func (p proxyConfig) buildArgs() []string {
	if p.empty() {
		return nil
	}
	h, s := withScheme(p.HTTP), withScheme(p.HTTPS)
	var out []string
	for _, kv := range []string{"HTTP_PROXY=" + h, "http_proxy=" + h, "HTTPS_PROXY=" + s, "https_proxy=" + s,
		"NO_PROXY=" + p.noProxy(""), "no_proxy=" + p.noProxy("")} {
		out = append(out, "--opt", "build-arg:"+kv)
	}
	return out
}

// registryHost strips the port from a registry address.
func registryHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
