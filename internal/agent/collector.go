package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/version"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// collector gathers what the agent reports about its node.
type collector struct {
	docker  *docker // nil when no Docker client could be configured
	started time.Time
}

func newCollector(d *docker) *collector {
	return &collector{docker: d, started: time.Now()}
}

// diskPath is the file system whose capacity matters: Docker's data
// directory if visible to the agent, otherwise the root file system.
func (c *collector) diskPath(ctx context.Context) string {
	if c.docker != nil {
		if p := c.docker.rootDir(ctx); p != "/" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return "/"
}

func (c *collector) nodeInfo(ctx context.Context) *agentv1.NodeInfo {
	hostname, _ := os.Hostname()
	memTotal, _, _ := memory()
	diskTotal, _, _ := disk(c.diskPath(ctx))
	info := &agentv1.NodeInfo{
		Hostname: hostname, Addresses: addresses(), CpuCount: int32(min(runtime.NumCPU(), 1<<31-1)), //nolint:gosec // G115: clamped.
		MemoryTotalBytes: memTotal, DiskTotalBytes: diskTotal,
		AgentVersion: version.Get().Version, Os: runtime.GOOS, Arch: runtime.GOARCH,
	}
	if c.docker != nil {
		if v, err := c.docker.version(ctx); err == nil {
			info.DockerVersion = v
		}
	}
	return info
}

func (c *collector) heartbeat(ctx context.Context) (*agentv1.Heartbeat, error) {
	_, available, _ := memory()
	load, _ := loadAverage()
	_, free, _ := disk(c.diskPath(ctx))
	hb := &agentv1.Heartbeat{
		MemoryAvailableBytes: available, CpuLoad_1M: load, DiskFreeBytes: free,
		AgentVersion: version.Get().Version, Uptime: durationpb.New(time.Since(c.started)),
	}
	var dockerErr error
	if c.docker == nil {
		dockerErr = errors.New("docker client not configured")
	} else if n, err := c.docker.runningContainers(ctx); err != nil {
		dockerErr = err
	} else {
		hb.RunningContainers, hb.DockerReachable = n, true
	}
	return hb, dockerErr
}

// addresses lists the node's non-loopback unicast IP addresses.
func addresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipnet.IP.String())
	}
	return out
}

// isCAMismatch reports whether a gRPC error came from a failed CA pin:
// the TLS failure surfaces as a status message, not a wrapped error.
func isCAMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), pki.ErrCAMismatch.Error())
}

// permanent reports whether retrying cannot help: the control plane does
// not accept this node's credentials any more.
func permanent(err error) bool {
	c := status.Code(err)
	return c == codes.PermissionDenied || c == codes.Unauthenticated
}

// describeRPCError turns a gRPC error into a message for the operator.
func describeRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("cannot reach the control plane: %s", st.Message())
	case codes.DeadlineExceeded:
		return errors.New("the control plane did not answer in time")
	default:
		return errors.New(st.Message())
	}
}
