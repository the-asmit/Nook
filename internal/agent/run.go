package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Config configures `nook-agent run`.
type Config struct {
	// StateDir holds the node identity written by `nook-agent join`.
	StateDir string `env:"NOOK_AGENT_STATE_DIR" envDefault:"/var/lib/nook-agent"`
	// HealthAddr serves /healthz, /readyz and /metrics; keep it on loopback.
	HealthAddr string `env:"NOOK_AGENT_HEALTH_ADDR" envDefault:"127.0.0.1:9101"`
	Log        logging.Config
	// ReconnectMin and ReconnectMax bound the reconnect backoff.
	ReconnectMin time.Duration `env:"NOOK_AGENT_RECONNECT_MIN" envDefault:"1s"`
	ReconnectMax time.Duration `env:"NOOK_AGENT_RECONNECT_MAX" envDefault:"60s"`
	// RenewCheckInterval is how often certificate expiry is checked.
	RenewCheckInterval time.Duration `env:"NOOK_AGENT_RENEW_CHECK_INTERVAL" envDefault:"10m"`
	// BuildSlots is how many builds run at once (0: the node does not build).
	BuildSlots int `env:"NOOK_AGENT_BUILD_SLOTS" envDefault:"2"`
	// BuildImage is the rootless BuildKit image builds run in, pinned by digest.
	BuildImage string `env:"NOOK_AGENT_BUILDKIT_IMAGE" envDefault:"moby/buildkit:v0.34.2-rootless@sha256:c8252268760e1baba80780d63d738ef9f260fb7c7c0973c78494cb9ddd99eda1"`
	// BuildNetwork is the network build containers join. The agent creates
	// it and the egress firewall always filters it (whatever its name).
	BuildNetwork string `env:"NOOK_AGENT_BUILD_NETWORK" envDefault:"nook-builds"`
	// BuildHosts maps host names to addresses for build containers
	// ("registry=10.0.0.5"), for a registry that is not in the node's DNS.
	BuildHosts []string `env:"NOOK_AGENT_BUILD_HOSTS" envSeparator:","`
	// BuildProxy passes the Docker engine's HTTP proxy settings to builds,
	// for nodes that reach the internet only through a proxy (which must
	// then be in BuildEgressAllow, and must refuse internal destinations).
	BuildProxy bool `env:"NOOK_AGENT_BUILD_PROXY" envDefault:"false"`
	// BuildMaxContextBytes limits the extracted size of a build context.
	BuildMaxContextBytes int64 `env:"NOOK_AGENT_BUILD_MAX_CONTEXT_BYTES" envDefault:"2147483648"`
	// AdvertiseAddr is the node's private IP address that app ports are
	// published on (never a wildcard address).
	AdvertiseAddr string `env:"NOOK_AGENT_ADVERTISE_ADDR"`
	// RegistryPullAddr is the registry's host:port as the agent itself
	// reaches it, when that differs from the address the control plane
	// names (build containers and the agent on different networks).
	RegistryPullAddr string `env:"NOOK_AGENT_REGISTRY_PULL_ADDR"`
	// CrashLimit crashes within CrashWindow make an instance crashed (no
	// more restarts).
	CrashLimit  int           `env:"NOOK_AGENT_CRASH_LIMIT" envDefault:"5"`
	CrashWindow time.Duration `env:"NOOK_AGENT_CRASH_WINDOW" envDefault:"10m"`
	// RestartBackoffMin and RestartBackoffMax bound the delay before a
	// crashed container is started again (doubling per crash).
	RestartBackoffMin time.Duration `env:"NOOK_AGENT_RESTART_BACKOFF_MIN" envDefault:"1s"`
	RestartBackoffMax time.Duration `env:"NOOK_AGENT_RESTART_BACKOFF_MAX" envDefault:"5m"`
	// EgressFilter installs the egress firewall for app and build
	// containers. Turning it off leaves cloud metadata and private
	// networks reachable from apps.
	EgressFilter bool `env:"NOOK_AGENT_EGRESS_FILTER" envDefault:"true"`
	// FirewallImage ships iptables; it runs briefly to install the rules.
	FirewallImage string `env:"NOOK_AGENT_FIREWALL_IMAGE" envDefault:"registry.k8s.io/build-image/distroless-iptables:v0.9.6@sha256:33f27a340efd1f0a0341bd85755f1752af00b27debaf2f2876a3ef5dcc07f84a"`
	// FirewallChain prefixes the agent's iptables chains.
	FirewallChain string `env:"NOOK_AGENT_FIREWALL_CHAIN" envDefault:"NOOK"`
	// BuildEgressAllow lists addresses (IPs or CIDRs) build containers may
	// reach although private: the registry.
	BuildEgressAllow []string `env:"NOOK_AGENT_BUILD_EGRESS_ALLOW" envSeparator:","`
	// EgressBlock lists more blocked destinations (IPs or CIDRs), such as
	// other nodes' public addresses.
	EgressBlock []string `env:"NOOK_AGENT_EGRESS_BLOCK" envSeparator:","`
}

// defaultBuildNetwork is the default build network.
const defaultBuildNetwork = "nook-builds"

// networkNamePattern is a Docker network name the agent may create.
var networkNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

// buildBridge names the Linux bridge of the build network: nkbuild0 for
// the default network, otherwise nkb + 12 hex digits of the name's hash
// (bridge names are at most 15 characters).
func buildBridge(network string) string {
	if network == defaultBuildNetwork {
		return "nkbuild0"
	}
	sum := sha256.Sum256([]byte(network))
	return "nkb" + hex.EncodeToString(sum[:])[:12]
}

// buildHostPattern is a host name for BuildHosts.
var buildHostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?$`)

// parseBuildHosts reads "name=ip" pairs.
func parseBuildHosts(list []string) ([][2]string, error) {
	var out [][2]string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		name, ip, ok := strings.Cut(s, "=")
		addr, err := netip.ParseAddr(ip)
		if !ok || err != nil || !buildHostPattern.MatchString(name) {
			return nil, fmt.Errorf("NOOK_AGENT_BUILD_HOSTS: %q is not name=ip", s)
		}
		out = append(out, [2]string{name, addr.Unmap().String()})
	}
	return out, nil
}

// parsePrefixes reads IPs and CIDRs.
func parsePrefixes(name string, list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not an IP address or CIDR", name, s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	errs := []error{
		config.CheckListenAddr("NOOK_AGENT_HEALTH_ADDR", c.HealthAddr),
		c.Log.Validate(),
		config.CheckDuration("NOOK_AGENT_RECONNECT_MIN", c.ReconnectMin, 10*time.Millisecond, time.Minute),
		config.CheckDuration("NOOK_AGENT_RECONNECT_MAX", c.ReconnectMax, c.ReconnectMin, time.Hour),
		config.CheckDuration("NOOK_AGENT_RENEW_CHECK_INTERVAL", c.RenewCheckInterval, 100*time.Millisecond, 24*time.Hour),
	}
	if c.StateDir == "" {
		errs = append(errs, errors.New("NOOK_AGENT_STATE_DIR must not be empty"))
	}
	errs = append(errs,
		config.CheckRange("NOOK_AGENT_BUILD_SLOTS", c.BuildSlots, 0, 64),
		config.CheckRange("NOOK_AGENT_BUILD_MAX_CONTEXT_BYTES", c.BuildMaxContextBytes, 1<<20, 1<<40))
	if !strings.Contains(c.BuildImage, "@sha256:") {
		errs = append(errs, errors.New("NOOK_AGENT_BUILDKIT_IMAGE must be pinned by digest (name:tag@sha256:...)"))
	}
	if !networkNamePattern.MatchString(c.BuildNetwork) {
		errs = append(errs, errors.New("NOOK_AGENT_BUILD_NETWORK must be a network name (lower-case letters, digits, '.', '_', '-')"))
	}
	if _, err := parseBuildHosts(c.BuildHosts); err != nil {
		errs = append(errs, err)
	}
	if a, err := netip.ParseAddr(c.AdvertiseAddr); err != nil || a.IsUnspecified() || a.IsMulticast() {
		errs = append(errs, errors.New("NOOK_AGENT_ADVERTISE_ADDR must be the node's private IP address (not 0.0.0.0 or ::)"))
	}
	if c.RegistryPullAddr != "" && !registryPattern.MatchString(c.RegistryPullAddr) {
		errs = append(errs, errors.New("NOOK_AGENT_REGISTRY_PULL_ADDR must be host:port"))
	}
	errs = append(errs,
		config.CheckRange("NOOK_AGENT_CRASH_LIMIT", c.CrashLimit, 1, 1000),
		config.CheckDuration("NOOK_AGENT_CRASH_WINDOW", c.CrashWindow, time.Second, 24*time.Hour),
		config.CheckDuration("NOOK_AGENT_RESTART_BACKOFF_MIN", c.RestartBackoffMin, 10*time.Millisecond, time.Hour),
		config.CheckDuration("NOOK_AGENT_RESTART_BACKOFF_MAX", c.RestartBackoffMax, c.RestartBackoffMin, 24*time.Hour))
	if !strings.Contains(c.FirewallImage, "@sha256:") {
		errs = append(errs, errors.New("NOOK_AGENT_FIREWALL_IMAGE must be pinned by digest (name:tag@sha256:...)"))
	}
	if !chainPattern.MatchString(c.FirewallChain) {
		errs = append(errs, errors.New("NOOK_AGENT_FIREWALL_CHAIN must be 1 to 20 upper-case letters, digits or hyphens, starting with a letter"))
	}
	if _, err := parsePrefixes("NOOK_AGENT_BUILD_EGRESS_ALLOW", c.BuildEgressAllow); err != nil {
		errs = append(errs, err)
	}
	if _, err := parsePrefixes("NOOK_AGENT_EGRESS_BLOCK", c.EgressBlock); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// healthyAfter: a session that lasted this long resets the backoff.
const healthyAfter = time.Minute

// connectTimeout bounds receiving ConnectAccepted after Hello.
const connectTimeout = 15 * time.Second

// Agent is a running nook-agent.
type Agent struct {
	cfg       Config
	dir       stateDir
	id        atomic.Pointer[identity]
	docker    *docker
	collector *collector
	metrics   *agentMetrics
	logger    *slog.Logger
	connected atomic.Bool
	// reconnect asks the current session to end so the next one presents
	// the renewed certificate.
	reconnect chan struct{}
	outbox    *outbox
	builder   *builder
	instances *instances
	// firewallReady is set once the egress firewall is installed (or
	// disabled); app and build containers wait for it.
	firewallReady atomic.Bool
	// buildsUnavailable says why builds cannot run on this node, or is "".
	buildsUnavailable atomic.Pointer[string]
}

// New loads the node identity and prepares the agent.
func New(cfg *Config, logger *slog.Logger) (*Agent, error) {
	dir := stateDir(cfg.StateDir)
	id, err := dir.load()
	if err != nil {
		return nil, err
	}
	d, err := newDocker()
	if err != nil {
		return nil, err
	}
	m, err := newAgentMetrics()
	if err != nil {
		_ = d.close()
		return nil, err
	}
	a := &Agent{cfg: *cfg, dir: dir, docker: d, collector: newCollector(d), metrics: m, logger: logger, reconnect: make(chan struct{}, 1), outbox: newOutbox()}
	a.id.Store(id)
	caPEM := func() []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.id.Load().ca.Raw})
	}
	a.builder = newBuilder(&a.cfg, d, a.outbox, logger, a.NodeID, caPEM)
	a.builder.ready = a.buildsReady
	advertise, err := netip.ParseAddr(cfg.AdvertiseAddr)
	if err != nil {
		_ = d.close()
		return nil, fmt.Errorf("NOOK_AGENT_ADVERTISE_ADDR: %w", err)
	}
	a.instances = &instances{
		docker: d, outbox: a.outbox, logger: logger, nodeID: a.NodeID, advertise: advertise.Unmap(), clock: realClock{},
		puller: &puller{docker: d, caPEM: caPEM, override: cfg.RegistryPullAddr, tmpDir: filepath.Join(cfg.StateDir, "pulls")},
		policy: crashPolicy{Limit: cfg.CrashLimit, Window: cfg.CrashWindow, MinBackoff: cfg.RestartBackoffMin, MaxBackoff: cfg.RestartBackoffMax},
		m:      map[string]*instance{}, logs: map[string]context.CancelFunc{},
	}
	empty := ""
	a.buildsUnavailable.Store(&empty)
	m.certExpiry.Set(float64(id.cert.NotAfter.Unix()))
	return a, nil
}

// Close releases the Docker client.
func (a *Agent) Close() error { return a.docker.close() }

// NodeID returns the node's ID.
func (a *Agent) NodeID() string { return a.id.Load().NodeID }

// Connected reports whether a session is established.
func (a *Agent) Connected() bool { return a.connected.Load() }

// Run keeps a session with the control plane until ctx is done or the
// control plane rejects this node permanently (for example after
// `nook node remove`), in which case it returns that error.
func (a *Agent) Run(ctx context.Context) error {
	if _, err := a.docker.version(ctx); err != nil {
		a.logger.WarnContext(ctx, "docker engine not reachable; heartbeats will report it", "error", err.Error())
	}
	if err := a.prepare(ctx); err != nil {
		return err
	}
	defer a.instances.close()
	// Builds still running when the agent stops report an infrastructure
	// error (delivered by the last session if it is still open), so the
	// control plane retries them on another node.
	defer a.builder.stop()
	renewErr := make(chan error, 1)
	go func() { renewErr <- a.renewLoop(ctx) }()

	attempt := 0
	for !done(ctx) {
		start := time.Now()
		err := a.connectOnce(ctx)
		a.connected.Store(false)
		if done(ctx) {
			break
		}
		if permanent(err) {
			return fmt.Errorf("the control plane rejected this node: %w", describeRPCError(err))
		}
		if time.Since(start) > healthyAfter {
			attempt = 0
		}
		delay := backoff(attempt, a.cfg.ReconnectMin, a.cfg.ReconnectMax)
		attempt++
		a.metrics.reconnects.Inc()
		if err != nil {
			a.logger.WarnContext(ctx, "disconnected from the control plane; reconnecting", "error", describeRPCError(err).Error(), "retry_in", delay.String())
		}
		select {
		case <-ctx.Done():
		case err := <-renewErr:
			return err
		case <-time.After(delay):
		}
	}
	return nil
}

// done reports whether ctx has ended (shutdown, not a failure).
func done(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// backoff returns a "full jitter" exponential delay: random in
// [0, min(max, min*2^attempt)], so many agents reconnecting after a
// control-plane restart do not arrive in lockstep.
func backoff(attempt int, minDelay, maxDelay time.Duration) time.Duration {
	ceiling := maxDelay
	if attempt < 30 {
		ceiling = min(maxDelay, minDelay<<attempt)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling)+1))
	if err != nil {
		return ceiling
	}
	return max(time.Duration(n.Int64()), minDelay/2)
}

// dial creates a mutually authenticated connection. The client
// certificate is read at handshake time, so a renewed certificate is used
// by the next connection.
func (a *Agent) dial() (*grpc.ClientConn, error) {
	id := a.id.Load()
	host, _, err := net.SplitHostPort(id.Server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", id.Server, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(id.ca)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: host,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return a.id.Load().tlsCertificate(), nil
		},
	}
	conn, err := grpc.NewClient(id.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", id.Server, err)
	}
	return conn, nil
}

// connectOnce runs one Connect stream until it fails or a reconnect is requested.
func (a *Agent) connectOnce(ctx context.Context) error {
	conn, err := a.dial()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// The stream outlives ctx briefly at shutdown, to report the results of
	// builds that the shutdown stops.
	shutdown := ctx
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()

	stream, err := agentv1.NewNodeServiceClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	info := a.collector.nodeInfo(ctx)
	info.BuildSlots = int32(a.cfg.BuildSlots) //nolint:gosec // G115: validated to be at most 64.
	info.AdvertiseAddress = a.cfg.AdvertiseAddr
	info.BuildsUnavailableReason = *a.buildsUnavailable.Load()
	hello := &agentv1.Hello{Info: info, ActiveBuildIds: a.builder.activeIDs(), Instances: a.instances.reports(ctx)}
	if err = stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Hello{Hello: hello}}); err != nil {
		return streamStatus(stream, err)
	}

	incoming := make(chan *agentv1.ConnectResponse)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, rerr := stream.Recv()
			if rerr != nil {
				recvErr <- rerr
				return
			}
			select {
			case incoming <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	acc, err := awaitAccepted(ctx, incoming, recvErr)
	if err != nil {
		return err
	}
	interval := max(acc.GetHeartbeatInterval().AsDuration(), time.Second)
	a.instances.restore(acc.GetInstances())
	a.connected.Store(true)
	a.logger.InfoContext(ctx, "connected to the control plane", "server", a.id.Load().Server, "heartbeat_interval", interval.String())

	results := make(chan *agentv1.CommandResult, 16)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if err := a.sendHeartbeat(ctx, stream); err != nil {
		return endStatus(ctx, incoming, recvErr, err)
	}
	for {
		select {
		case <-shutdown.Done():
			a.builder.stop()
			a.flushOutbox(stream)
			return nil
		case <-a.outbox.ready:
			if err := a.sendOutbox(stream); err != nil {
				return endStatus(ctx, incoming, recvErr, err)
			}
		case <-a.reconnect:
			a.logger.InfoContext(ctx, "reconnecting to present the renewed certificate")
			return nil
		case err := <-recvErr:
			return err
		case <-ticker.C:
			if err := a.sendHeartbeat(ctx, stream); err != nil {
				return endStatus(ctx, incoming, recvErr, err)
			}
		case m := <-incoming:
			if cmd := m.GetCommand(); cmd != nil {
				go func() { results <- a.execute(ctx, cmd) }()
			}
		case res := <-results:
			if err := stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_CommandResult{CommandResult: res}}); err != nil {
				return endStatus(ctx, incoming, recvErr, err)
			}
		}
	}
}

// streamStatus turns a failed Send into the stream's real outcome. gRPC
// reports a stream the server has ended as io.EOF on Send; the status
// that says why (for example PermissionDenied after `nook node remove`)
// is only available from Recv.
func streamStatus(stream agentv1.NodeService_ConnectClient, err error) error {
	if !errors.Is(err, io.EOF) {
		return err
	}
	for {
		if _, rerr := stream.Recv(); rerr != nil {
			return rerr
		}
	}
}

// endStatus is streamStatus once the receiving goroutine owns Recv: the
// final status arrives on recvErr.
// Messages still in flight are discarded so the goroutine reaches it.
func endStatus(ctx context.Context, incoming <-chan *agentv1.ConnectResponse, recvErr <-chan error, err error) error {
	if !errors.Is(err, io.EOF) {
		return err
	}
	timer := time.NewTimer(connectTimeout)
	defer timer.Stop()
	for {
		select {
		case rerr := <-recvErr:
			return rerr
		case <-incoming:
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return err
		}
	}
}

func awaitAccepted(ctx context.Context, incoming <-chan *agentv1.ConnectResponse, recvErr <-chan error) (*agentv1.ConnectAccepted, error) {
	timer := time.NewTimer(connectTimeout)
	defer timer.Stop()
	select {
	case m := <-incoming:
		acc := m.GetAccepted()
		if acc == nil {
			return nil, errors.New("control plane did not accept the connection")
		}
		return acc, nil
	case err := <-recvErr:
		return nil, err
	case <-timer.C:
		return nil, errors.New("timed out waiting for the control plane to accept the connection")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// sendOutbox sends queued build output and results in order; what could
// not be sent stays queued for the next stream.
func (a *Agent) sendOutbox(stream agentv1.NodeService_ConnectClient) error {
	items := a.outbox.take()
	for i, m := range items {
		if err := stream.Send(m); err != nil {
			a.outbox.requeue(items[i:])
			return err
		}
	}
	return nil
}

// flushOutbox makes a bounded last attempt to deliver the outbox at shutdown.
func (a *Agent) flushOutbox(stream agentv1.NodeService_ConnectClient) {
	deadline := time.Now().Add(5 * time.Second)
	for !a.outbox.empty() && time.Now().Before(deadline) {
		if a.sendOutbox(stream) != nil {
			return
		}
	}
	_ = stream.CloseSend()
}

func (a *Agent) sendHeartbeat(ctx context.Context, stream agentv1.NodeService_ConnectClient) error {
	hb, dockerErr := a.collector.heartbeat(ctx)
	hb.BuildsUnavailableReason = *a.buildsUnavailable.Load()
	if dockerErr != nil {
		a.logger.WarnContext(ctx, "heartbeat without docker data", "error", dockerErr.Error())
	}
	if err := stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Heartbeat{Heartbeat: hb}}); err != nil {
		return err
	}
	a.metrics.heartbeats.Inc()
	return nil
}
