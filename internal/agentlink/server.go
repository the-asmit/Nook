package agentlink

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/metrics"
	"github.com/the-asmit/nook/internal/ratelimit"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Transport limits, each chosen deliberately.
const (
	// maxMessageSize: the largest message is an inspection result listing
	// containers; agents cap that list well below this.
	maxMessageSize = 1 << 20
	// maxStreams per connection: an agent needs one Connect stream plus the
	// occasional unary call.
	maxStreams = 16
	// keepaliveTime: the server pings an idle connection after this long
	// and drops it if no answer comes within keepaliveTimeout, so a dead
	// agent's stream is cleaned up even if no heartbeat arrives.
	keepaliveTime    = 30 * time.Second
	keepaliveTimeout = 10 * time.Second
	// minClientPing: clients pinging more often than this are disconnected.
	minClientPing = 10 * time.Second
	// handshakeTimeout bounds the TLS handshake of a new connection.
	handshakeTimeout = 10 * time.Second
	// gracefulStopTimeout bounds waiting for unary calls at shutdown.
	gracefulStopTimeout = 10 * time.Second
	// serverCertTTL is the lifetime of each instance's gRPC server certificate.
	serverCertTTL = 30 * 24 * time.Hour
)

// Deps are the collaborators of the gRPC server.
type Deps struct {
	Registry *nodes.Registry
	Hub      *Hub
	CA       *pki.CA
	Limiter  *ratelimit.Limiter
	Metrics  prometheus.Registerer
	Logger   *slog.Logger
}

// Server is the agent-facing gRPC server.
type Server struct {
	agentv1.UnimplementedNodeServiceServer
	registry *nodes.Registry
	hub      *Hub
	ca       *pki.CA
	limiter  *ratelimit.Limiter
	logger   *slog.Logger
	grpc     *grpc.Server
	listener net.Listener
	health   *health.Server
}

// Listen binds the gRPC listener and builds the server. names are the
// host names and IPs the server certificate covers.
func Listen(ctx context.Context, addr string, names []string, d *Deps) (*Server, error) {
	certs, err := pki.NewServerCerts(d.CA, names, serverCertTTL)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: certs.GetCertificate,
		// A client certificate is optional at the TLS layer (Join has none)
		// but, when present, must chain to the Nook CA; the RPC handlers
		// then require one for everything except Join.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  d.CA.Pool(),
	}
	m, err := newMetrics(d.Metrics)
	if err != nil {
		return nil, err
	}
	s := &Server{registry: d.Registry, hub: d.Hub, ca: d.CA, limiter: d.Limiter, logger: d.Logger, health: health.NewServer()}
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ConnectionTimeout(handshakeTimeout),
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.MaxSendMsgSize(maxMessageSize),
		grpc.MaxConcurrentStreams(maxStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: keepaliveTime, Timeout: keepaliveTimeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: minClientPing, PermitWithoutStream: true}),
		grpc.ChainUnaryInterceptor(s.unaryRecover, m.unary(d.Logger)),
		grpc.ChainStreamInterceptor(s.streamRecover, m.stream(d.Logger)), //nolint:contextcheck // gRPC gives every stream its own context (ss.Context()).
	)
	agentv1.RegisterNodeServiceServer(s.grpc, s)
	healthpb.RegisterHealthServer(s.grpc, s.health)

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.listener = ln
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// Serve handles RPCs until ctx is done, then ends every agent stream
// (agents reconnect, possibly to another instance) and stops.
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.grpc.Serve(s.listener) }()
	select {
	case err := <-errCh:
		return fmt.Errorf("grpc server stopped unexpectedly: %w", err)
	case <-ctx.Done():
	}
	s.health.Shutdown()
	s.hub.closeAll(errShuttingDown)
	stopped := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(gracefulStopTimeout):
		s.grpc.Stop()
	}
	if err := <-errCh; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("grpc server: %w", err)
	}
	s.logger.InfoContext(ctx, "grpc server stopped")
	return nil
}

var errShuttingDown = errors.New("control-plane instance is shutting down")

func (s *Server) unaryRecover(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.ErrorContext(ctx, "panic in gRPC handler", "method", info.FullMethod, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(ctx, req)
}

func (s *Server) streamRecover(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.ErrorContext(ss.Context(), "panic in gRPC stream", "method", info.FullMethod, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	return handler(srv, ss)
}

// grpcMetrics counts RPCs and live agent streams.
type grpcMetrics struct {
	calls   *prometheus.CounterVec
	streams prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) (*grpcMetrics, error) {
	m := &grpcMetrics{
		calls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "grpc", Name: "calls_total",
			Help: "Agent RPCs handled, by method and status code.",
		}, []string{"method", "code"}),
		streams: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace, Subsystem: "grpc", Name: "agent_streams",
			Help: "Agent Connect streams currently open on this instance.",
		}),
	}
	for _, c := range []prometheus.Collector{m.calls, m.streams} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register grpc metrics: %w", err)
		}
	}
	return m, nil
}

func (m *grpcMetrics) unary(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)
		m.calls.WithLabelValues(info.FullMethod, code.String()).Inc()
		logger.InfoContext(ctx, "grpc call", "method", info.FullMethod, "code", code.String(),
			"duration_ms", float64(time.Since(start).Microseconds())/1000, "peer", peerAddr(ctx))
		return resp, err
	}
}

func (m *grpcMetrics) stream(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		m.streams.Inc()
		err := handler(srv, ss)
		m.streams.Dec()
		code := status.Code(err)
		m.calls.WithLabelValues(info.FullMethod, code.String()).Inc()
		logger.InfoContext(ss.Context(), "grpc stream ended", "method", info.FullMethod, "code", code.String(),
			"duration_ms", float64(time.Since(start).Microseconds())/1000, "peer", peerAddr(ss.Context()))
		return err
	}
}

// Close releases the listener of a server that never started serving
// (for example when a later startup step failed). Serve stops it otherwise.
func (s *Server) Close() {
	_ = s.listener.Close() // Already closed when Serve ran; nothing to report.
}
