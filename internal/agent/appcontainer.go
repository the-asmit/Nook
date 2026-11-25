package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Labels on app containers and networks. The agent finds its instances by
// them after a restart, so they also carry what it needs to health-check
// an adopted container.
const (
	instanceLabel       = "nook.instance"
	appLabel            = "nook.app"
	workspaceLabel      = "nook.workspace"
	deploymentLabel     = "nook.deployment"
	nodeLabel           = "nook.node"
	portLabel           = "nook.port"
	healthPathLabel     = "nook.health_path"
	startupTimeoutLabel = "nook.startup_timeout"
)

// Limits the agent applies to every app container.
const (
	appPIDsLimit    = 1024
	appTmpfsOptions = "rw,noexec,nosuid,nodev,size=67108864"
	appLogMaxSize   = "10m"
	appLogMaxFiles  = "3"
	// appStopGrace is how long an app gets to exit after SIGTERM.
	appStopGrace = 10
	// appBridgePrefix names the bridge interfaces of app networks; the
	// egress firewall matches them by this prefix.
	appBridgePrefix = "nka"
	// healthPoll and healthRequestTimeout pace health checks.
	healthPoll           = 500 * time.Millisecond
	healthRequestTimeout = 2 * time.Second
	// startupLogLines is how much output a failed instance keeps.
	startupLogLines = 200
	maxAppMemory    = 1 << 40
	maxAppMillicore = 1024000
	maxStartup      = time.Hour
)

func containerName(instanceID string) string { return "nook-app-" + instanceID }

// appNetwork is the per-app bridge network: only the app's own containers
// are on it, inter-container traffic on it is off, and its bridge name
// carries the prefix the egress firewall matches.
func appNetwork(appID string) (name, bridge string) {
	hex := strings.ReplaceAll(appID, "-", "")
	return "nook-app-" + appID, appBridgePrefix + hex[len(hex)-12:]
}

func validateStart(cmd *agentv1.StartInstanceCommand) error {
	switch {
	case !buildIDPattern.MatchString(cmd.GetInstanceId()), !buildIDPattern.MatchString(cmd.GetAppId()),
		!buildIDPattern.MatchString(cmd.GetDeploymentId()), !buildIDPattern.MatchString(cmd.GetWorkspaceId()):
		return errors.New("invalid ids")
	case !validDigest(cmd.GetImageDigest()), !refPartPattern.MatchString(cmd.GetRepository()), !registryPattern.MatchString(cmd.GetRegistry()):
		return errors.New("invalid image")
	case cmd.GetPort() < 1 || cmd.GetPort() > 65535:
		return errors.New("invalid port")
	case !validHealthPath(cmd.GetHealthCheckPath()):
		return errors.New("invalid health check path")
	case cmd.GetRegistryToken() == "":
		return errors.New("a registry token is required")
	case cmd.GetMemoryBytes() < 4<<20 || cmd.GetMemoryBytes() > maxAppMemory, cmd.GetCpuMillicores() < 1 || cmd.GetCpuMillicores() > maxAppMillicore:
		return errors.New("invalid limits")
	}
	for _, e := range cmd.GetEnv() {
		if e.GetName() == "" || strings.ContainsAny(e.GetName(), "=\x00") || strings.ContainsRune(e.GetValue(), 0) {
			return errors.New("invalid environment")
		}
	}
	return nil
}

func validHealthPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 200 {
		return false
	}
	for i := range len(p) {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// appContainerSpec is an app container: the image's own user, every
// capability dropped, no privilege escalation, Docker's default seccomp
// profile, hard memory/CPU/PID limits, no mounts from the host (only a
// tmpfs /tmp), rotated logs, its own network, and its port published only
// on the node's advertise address.
func (m *instances) appContainerSpec(cmd *agentv1.StartInstanceCommand, image, networkName string) (client.ContainerCreateOptions, error) {
	port, err := network.ParsePort(strconv.Itoa(int(cmd.GetPort())) + "/tcp")
	if err != nil {
		return client.ContainerCreateOptions{}, fmt.Errorf("app port: %w", err)
	}
	env := make([]string, 0, len(cmd.GetEnv()))
	for _, e := range cmd.GetEnv() {
		env = append(env, e.GetName()+"="+e.GetValue())
	}
	pids := int64(appPIDsLimit)
	startup := min(max(cmd.GetStartupTimeout().AsDuration(), time.Second), maxStartup)
	return client.ContainerCreateOptions{
		Name: containerName(cmd.GetInstanceId()),
		Config: &container.Config{
			Image:        image,
			Env:          env,
			ExposedPorts: network.PortSet{port: struct{}{}},
			Labels: map[string]string{
				ManagedLabel: "true", instanceLabel: cmd.GetInstanceId(), appLabel: cmd.GetAppId(),
				workspaceLabel: cmd.GetWorkspaceId(), deploymentLabel: cmd.GetDeploymentId(), nodeLabel: m.nodeID(),
				portLabel: strconv.Itoa(int(cmd.GetPort())), healthPathLabel: cmd.GetHealthCheckPath(),
				startupTimeoutLabel: startup.String(),
			},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    container.NetworkMode(networkName),
			PortBindings:   network.PortMap{port: []network.PortBinding{{HostIP: m.advertise}}},
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			ReadonlyRootfs: cmd.GetReadOnlyRootfs(),
			Tmpfs:          map[string]string{"/tmp": appTmpfsOptions},
			RestartPolicy:  container.RestartPolicy{Name: container.RestartPolicyDisabled},
			LogConfig: container.LogConfig{Type: "json-file", Config: map[string]string{
				"max-size": appLogMaxSize, "max-file": appLogMaxFiles,
			}},
			Resources: container.Resources{
				Memory: cmd.GetMemoryBytes(), MemorySwap: cmd.GetMemoryBytes(),
				NanoCPUs: cmd.GetCpuMillicores() * 1_000_000, PidsLimit: &pids,
			},
		},
	}, nil
}

// ensureAppNetwork creates the app's network unless it exists.
func (m *instances) ensureAppNetwork(ctx context.Context, appID string) (string, error) {
	name, bridge := appNetwork(appID)
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	if _, err := m.docker.client.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		return name, nil
	}
	enableIPv6 := false
	_, err := m.docker.client.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver:     "bridge",
		EnableIPv6: &enableIPv6,
		Options: map[string]string{
			"com.docker.network.bridge.name":       bridge,
			"com.docker.network.bridge.enable_icc": "false",
		},
		Labels: map[string]string{ManagedLabel: "true", appLabel: appID},
	})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return "", fmt.Errorf("create app network: %w", err)
	}
	return name, nil
}

// removeAppNetwork deletes the app's network once no container uses it.
func (m *instances) removeAppNetwork(ctx context.Context, appID string) {
	name, _ := appNetwork(appID)
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	list, err := m.docker.client.ContainerList(ctx, client.ContainerListOptions{
		All: true, Filters: client.Filters{}.Add("label", appLabel+"="+appID),
	})
	if err != nil || len(list.Items) > 0 {
		return
	}
	// Another agent on the same engine may attach a container meanwhile;
	// the engine refuses to remove a network in use.
	_, _ = m.docker.client.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
}

// healthURL is where the app answers its health check: its published
// port on the advertise address, the way the gateway will reach it.
func (m *instances) healthURL(hostPort int, path string) string {
	return "http://" + net.JoinHostPort(m.advertise.String(), strconv.Itoa(hostPort)) + path
}

// exitedError means the container stopped while being health-checked.
type exitedError struct{ reason string }

func (e exitedError) Error() string { return e.reason }

// waitHealthy polls the health check until it answers 2xx, the container
// exits or the timeout passes.
func (m *instances) waitHealthy(ctx context.Context, containerID string, hostPort int, path string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hc := &http.Client{
		Timeout:       healthRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := m.healthURL(hostPort, path)
	last := "no answer yet"
	for {
		if reason, running := m.containerState(ctx, containerID); !running {
			return exitedError{reason: reason}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return fmt.Errorf("health check request: %w", err)
		}
		resp, err := hc.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			last = "it answered HTTP " + strconv.Itoa(resp.StatusCode)
		} else if ctx.Err() == nil {
			last = "it did not answer"
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("the health check GET %s did not answer 2xx within %s (%s)", path, timeout, last)
			}
			return ctx.Err()
		case <-time.After(healthPoll):
		}
	}
}

// containerState reports whether a container runs and, if not, why.
func (m *instances) containerState(ctx context.Context, id string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := m.docker.client.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil || info.Container.State == nil {
		return "the container disappeared", false
	}
	st := info.Container.State
	if st.Running {
		return "", true
	}
	if st.OOMKilled {
		return "the app ran out of memory and was killed", false
	}
	return "the app exited with code " + strconv.Itoa(st.ExitCode), false
}

// hostPort returns the port published for the app's port.
func (m *instances) hostPort(ctx context.Context, id string, port int32) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := m.docker.client.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("inspect container: %w", err)
	}
	if info.Container.NetworkSettings == nil {
		return 0, errors.New("the container has no network settings")
	}
	p, err := network.ParsePort(strconv.Itoa(int(port)) + "/tcp")
	if err != nil {
		return 0, fmt.Errorf("app port: %w", err)
	}
	for _, b := range info.Container.NetworkSettings.Ports[p] {
		if b.HostIP.Unmap() == m.advertise {
			if n, err := strconv.Atoi(b.HostPort); err == nil {
				return n, nil
			}
		}
	}
	return 0, errors.New("the app's port is not published on the advertise address")
}

// tailLog returns the container's last lines of output.
func (m *instances) tailLog(ctx context.Context, id string) []string {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	rc, err := m.docker.client.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: strconv.Itoa(startupLogLines)})
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	var buf bytes.Buffer
	_, _ = stdcopy.StdCopy(&buf, &buf, io.LimitReader(rc, maxStartupLogBytes))
	var lines []string
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// maxStartupLogBytes bounds the output kept from a failed instance.
const maxStartupLogBytes = 64 << 10
