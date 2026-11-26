package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/moby/moby/client"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Labels on build containers. A restarted agent removes the containers of
// its own node that it no longer tracks.
const (
	buildLabel     = "nook.build"
	buildNodeLabel = "nook.build.node"
)

// Limits the agent applies regardless of what a command asks for.
const (
	maxBuildTimeout   = 2 * time.Hour
	maxBuildLogBytes  = 64 << 20
	maxBuildMemory    = 64 << 30
	minBuildMemory    = 128 << 20
	maxBuildMillicore = 64000
	// buildPIDsLimit caps processes in a build container (fork bombs).
	buildPIDsLimit = 4096
	// stopGrace bounds reporting results when the agent shuts down.
	stopGrace = 15 * time.Second
)

var (
	errBusy         = errors.New("no free build slot")
	errShuttingDown = errors.New("the agent is shutting down")
	errCanceled     = errors.New("canceled")
	buildIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	refPartPattern  = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	tagPattern      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	registryPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?(:[0-9]{1,5})?$`)
)

// builder runs builds: at most cfg.BuildSlots at once, each in its own
// short-lived, locked-down BuildKit container.
type builder struct {
	cfg    *Config
	docker *docker
	outbox *outbox
	logger *slog.Logger
	nodeID func() string
	caPEM  func() []byte
	// ready reports whether builds may run on the node now.
	ready func() error
	// resolvers returns the node's DNS resolvers for RUN steps (nil: not
	// known; BuildKit then uses its defaults).
	resolvers func() []netip.Addr

	mu      sync.Mutex
	running map[string]*runningBuild
	wg      sync.WaitGroup
	stopped bool
}

type runningBuild struct {
	cancel context.CancelCauseFunc
}

func newBuilder(cfg *Config, d *docker, out *outbox, logger *slog.Logger, nodeID func() string, caPEM func() []byte) *builder {
	return &builder{cfg: cfg, docker: d, outbox: out, logger: logger, nodeID: nodeID, caPEM: caPEM, running: map[string]*runningBuild{}}
}

// validate checks a build command from the control plane before any of
// its values reach the Docker engine.
func validateBuild(cmd *agentv1.BuildCommand) error {
	switch {
	case !buildIDPattern.MatchString(cmd.GetBuildId()):
		return errors.New("invalid build id")
	case !sha256Pattern.MatchString(cmd.GetSourceSha256()) || cmd.GetSourceSize() <= 0:
		return errors.New("invalid source checksum or size")
	case !refPartPattern.MatchString(cmd.GetRepository()) || !tagPattern.MatchString(cmd.GetTag()):
		return errors.New("invalid image name")
	case !registryPattern.MatchString(cmd.GetRegistry()):
		return errors.New("invalid registry address")
	case cmd.GetSourceUrl() == "" || cmd.GetRegistryToken() == "":
		return errors.New("source and registry token are required")
	}
	return nil
}

// start begins a build in the background. It fails at once if no slot is
// free; the result arrives later through the outbox.
func (b *builder) start(cmd *agentv1.BuildCommand) error {
	if err := validateBuild(cmd); err != nil {
		return err
	}
	if b.ready != nil {
		if err := b.ready(); err != nil {
			return err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return errShuttingDown
	}
	if _, ok := b.running[cmd.GetBuildId()]; ok {
		// A repeated command for a build already running is accepted:
		// the control plane may resend after a reconnect.
		return nil
	}
	if len(b.running) >= b.cfg.BuildSlots {
		return errBusy
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	b.running[cmd.GetBuildId()] = &runningBuild{cancel: cancel}
	b.wg.Go(func() {
		defer cancel(nil)
		result := b.run(ctx, cmd)
		b.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_BuildFinished{BuildFinished: result}})
		b.mu.Lock()
		delete(b.running, cmd.GetBuildId())
		b.mu.Unlock()
		b.logger.Info("build finished", "build_id", cmd.GetBuildId(), "result", result.GetResult().String())
	})
	return nil
}

// cancelBuild stops a running build; it reports whether the build was
// running.
func (b *builder) cancelBuild(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.running[id]
	if ok {
		r.cancel(errCanceled)
	}
	return ok
}

// activeIDs lists running builds and finished builds whose results have
// not been delivered yet, for the Hello of a new stream.
func (b *builder) activeIDs() []string {
	b.mu.Lock()
	ids := make([]string, 0, len(b.running))
	for id := range b.running {
		ids = append(ids, id)
	}
	b.mu.Unlock()
	ids = append(ids, b.outbox.pendingResults()...)
	sort.Strings(ids)
	return ids
}

// stop cancels every build (they report an infrastructure error, so the
// control plane retries elsewhere) and waits for them, at most stopGrace.
func (b *builder) stop() {
	b.mu.Lock()
	b.stopped = true
	for _, r := range b.running {
		r.cancel(errShuttingDown)
	}
	b.mu.Unlock()
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopGrace):
		b.logger.Warn("builds did not stop in time")
	}
}

// removeOrphans deletes build containers and directories this node left
// behind (for example after the agent was killed).
func (b *builder) removeOrphans(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	list, err := b.docker.client.ContainerList(ctx, client.ContainerListOptions{
		All: true, Filters: client.Filters{}.Add("label", buildNodeLabel+"="+b.nodeID()),
	})
	if err != nil {
		b.logger.Warn("could not list leftover build containers", "error", err.Error())
	} else {
		for i := range list.Items {
			c := &list.Items[i]
			if _, err := b.docker.client.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
				b.logger.Warn("could not remove leftover build container", "container", c.ID, "error", err.Error())
				continue
			}
			b.logger.Info("removed leftover build container", "container", c.ID, "build_id", c.Labels[buildLabel])
		}
	}
	dir := filepath.Join(b.cfg.StateDir, "builds")
	if err := os.RemoveAll(dir); err != nil {
		b.logger.Warn("could not remove leftover build directories", "error", err.Error())
	}
}

func (b *builder) buildDir(id string) string {
	return filepath.Join(b.cfg.StateDir, "builds", id)
}

// result builds a BuildFinished message (withLog adds the log size).
func result(id string, r agentv1.BuildResult, msg string) *agentv1.BuildFinished {
	return &agentv1.BuildFinished{BuildId: id, Result: r, Message: msg}
}

func infraError(id, msg string) *agentv1.BuildFinished {
	return result(id, agentv1.BuildResult_BUILD_RESULT_INFRA_ERROR, msg)
}
