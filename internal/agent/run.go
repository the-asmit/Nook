package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
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
	a := &Agent{cfg: *cfg, dir: dir, docker: d, collector: newCollector(d), metrics: m, logger: logger, reconnect: make(chan struct{}, 1)}
	a.id.Store(id)
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := agentv1.NewNodeServiceClient(conn).Connect(ctx)
	if err != nil {
		return err
	}
	if err = stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{Info: a.collector.nodeInfo(ctx)}}}); err != nil {
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

	interval, err := awaitAccepted(ctx, incoming, recvErr)
	if err != nil {
		return err
	}
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
		case <-ctx.Done():
			return nil
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

func awaitAccepted(ctx context.Context, incoming <-chan *agentv1.ConnectResponse, recvErr <-chan error) (time.Duration, error) {
	timer := time.NewTimer(connectTimeout)
	defer timer.Stop()
	select {
	case m := <-incoming:
		acc := m.GetAccepted()
		if acc == nil {
			return 0, errors.New("control plane did not accept the connection")
		}
		return max(acc.GetHeartbeatInterval().AsDuration(), time.Second), nil
	case err := <-recvErr:
		return 0, err
	case <-timer.C:
		return 0, errors.New("timed out waiting for the control plane to accept the connection")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context, stream agentv1.NodeService_ConnectClient) error {
	hb, dockerErr := a.collector.heartbeat(ctx)
	if dockerErr != nil {
		a.logger.WarnContext(ctx, "heartbeat without docker data", "error", dockerErr.Error())
	}
	if err := stream.Send(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Heartbeat{Heartbeat: hb}}); err != nil {
		return err
	}
	a.metrics.heartbeats.Inc()
	return nil
}

// maxCommandTimeout caps what the control plane may ask for.
const maxCommandTimeout = 5 * time.Minute

// execute runs one command within its timeout and returns its result.
func (a *Agent) execute(ctx context.Context, cmd *agentv1.Command) *agentv1.CommandResult {
	timeout := min(max(cmd.GetTimeout().AsDuration(), time.Second), maxCommandTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := &agentv1.CommandResult{CommandId: cmd.GetCommandId()}
	fail := func(code agentv1.CommandErrorCode, msg string) *agentv1.CommandResult {
		res.Result = &agentv1.CommandResult_Error{Error: &agentv1.CommandError{Code: code, Message: msg}}
		a.metrics.commands.WithLabelValues(kindOf(cmd), "error").Inc()
		return res
	}
	switch cmd.GetKind().(type) {
	case *agentv1.Command_InspectNode:
		out, err := a.docker.inspect(ctx)
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_TIMEOUT, "inspection did not finish in "+timeout.String())
		case err != nil:
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_DOCKER_UNAVAILABLE, err.Error())
		}
		res.Result = &agentv1.CommandResult_InspectNode{InspectNode: out}
	default:
		return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_UNSUPPORTED, "this agent does not support the command; upgrade nook-agent")
	}
	a.metrics.commands.WithLabelValues(kindOf(cmd), "ok").Inc()
	return res
}

func kindOf(cmd *agentv1.Command) string {
	if cmd.GetInspectNode() != nil {
		return "inspect_node"
	}
	return "unknown"
}
