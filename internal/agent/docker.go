package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

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
