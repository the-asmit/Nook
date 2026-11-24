package agentlink

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/ratelimit"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// joinRule limits join attempts per source address. Tokens are 256-bit,
// so this is about load, not guessing.
var joinRule = ratelimit.Rule{Name: "node_join", Limit: 20, Window: time.Minute}

// helloTimeout bounds how long a new stream may stay silent.
const helloTimeout = 10 * time.Second

// rpcTimeout bounds the work of a unary RPC on the server.
const rpcTimeout = 30 * time.Second

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

func peerIP(ctx context.Context) *netip.Addr {
	ap, err := netip.ParseAddrPort(peerAddr(ctx))
	if err != nil {
		return nil
	}
	addr := ap.Addr().Unmap()
	return &addr
}

// toStatus maps an error to a gRPC status. Classified errors keep their
// message; anything else is logged and reported as a bare internal error,
// so no internal detail ever reaches an agent.
func (s *Server) toStatus(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, nodes.ErrNodeRemoved):
		return status.Error(codes.PermissionDenied, "this node has been removed from Nook; join it again with a new token")
	case errors.Is(err, nodes.ErrCertificateRevoked), errors.Is(err, nodes.ErrUnknownCertificate):
		return status.Error(codes.Unauthenticated, "the client certificate is not accepted")
	}
	if e, ok := apperr.As(err); ok {
		code := codes.Internal
		switch e.Kind {
		case apperr.KindInvalid:
			code = codes.InvalidArgument
		case apperr.KindUnauthenticated:
			code = codes.Unauthenticated
		case apperr.KindForbidden:
			code = codes.PermissionDenied
		case apperr.KindNotFound:
			code = codes.NotFound
		case apperr.KindConflict:
			code = codes.AlreadyExists
		case apperr.KindRateLimited:
			code = codes.ResourceExhausted
		case apperr.KindUnavailable:
			code = codes.Unavailable
		case apperr.KindTimeout:
			code = codes.DeadlineExceeded
		}
		return status.Error(code, e.Message)
	}
	if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		// The agent went away (or the call's deadline passed) while we
		// were working for it: nothing failed on our side.
		return status.FromContextError(ctx.Err()).Err()
	}
	s.logger.ErrorContext(ctx, "agent RPC failed", "error", err.Error())
	return status.Error(codes.Internal, "internal error")
}

// authenticate identifies the node from its verified client certificate
// and checks the certificate against the database.
func (s *Server) authenticate(ctx context.Context) (nodes.Identity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nodes.Identity{}, status.Error(codes.Unauthenticated, "a client certificate is required")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return nodes.Identity{}, status.Error(codes.Unauthenticated, "a client certificate is required")
	}
	cert := info.State.VerifiedChains[0][0]
	id, err := s.registry.Authenticate(ctx, cert)
	if err != nil {
		s.logger.WarnContext(ctx, "agent authentication failed", "peer", peerAddr(ctx), "serial", serialOf(cert), "error", err.Error())
		return nodes.Identity{}, s.toStatus(ctx, err)
	}
	return id, nil
}

func serialOf(c *x509.Certificate) string { return c.SerialNumber.Text(16) }

// Join implements agentv1.NodeServiceServer.
func (s *Server) Join(ctx context.Context, req *agentv1.JoinRequest) (*agentv1.JoinResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	res, err := s.limiter.Allow(ctx, joinRule, peerAddr(ctx))
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	if !res.Allowed {
		return nil, status.Error(codes.ResourceExhausted, "too many join attempts; retry later")
	}
	joined, err := s.registry.Join(ctx, &nodes.JoinRequest{
		Token: req.GetJoinToken(), CSR: req.GetCsrDer(), Name: req.GetName(), Labels: req.GetLabels(),
		Info: infoFromProto(req.GetInfo()), IP: peerIP(ctx),
	})
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	s.logger.InfoContext(ctx, "node joined", "node", joined.Node.Name, "node_id", joined.Node.ID.String(), "peer", peerAddr(ctx))
	return &agentv1.JoinResponse{
		NodeId: joined.Node.ID.String(), Name: joined.Node.Name,
		CertificateDer: joined.Cert.DER, CaCertificateDer: s.ca.Certificate().Raw,
	}, nil
}

// RenewCertificate implements agentv1.NodeServiceServer.
func (s *Server) RenewCertificate(ctx context.Context, req *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	id, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := s.registry.Renew(ctx, id, req.GetCsrDer())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	s.logger.InfoContext(ctx, "node certificate renewed", "node", id.Name, "not_after", cert.Cert.NotAfter)
	return &agentv1.RenewCertificateResponse{CertificateDer: cert.DER, CaCertificateDer: s.ca.Certificate().Raw}, nil
}

func infoFromProto(i *agentv1.NodeInfo) nodes.Info {
	return nodes.Info{
		Hostname: i.GetHostname(), Addresses: i.GetAddresses(), CPUCount: i.GetCpuCount(),
		MemoryTotalBytes: i.GetMemoryTotalBytes(), DiskTotalBytes: i.GetDiskTotalBytes(),
		DockerVersion: i.GetDockerVersion(), AgentVersion: i.GetAgentVersion(), OS: i.GetOs(), Arch: i.GetArch(),
	}
}

// Connect implements agentv1.NodeServiceServer: the agent's long-lived session.
func (s *Server) Connect(stream agentv1.NodeService_ConnectServer) error {
	ctx := stream.Context()
	id, err := s.authenticate(ctx)
	if err != nil {
		return err
	}

	// One goroutine owns Recv; the handler selects on what it receives.
	msgs := make(chan *agentv1.ConnectRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, rerr := stream.Recv()
			if rerr != nil {
				recvErr <- rerr
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	hello, err := awaitHello(ctx, msgs, recvErr)
	if err != nil {
		return err
	}
	info := infoFromProto(hello.GetInfo())
	if err = s.registry.UpdateInfo(ctx, id.NodeID, &info); err != nil {
		return s.toStatus(ctx, err)
	}
	sess, err := s.hub.register(ctx, id.NodeID)
	if err != nil {
		return s.toStatus(ctx, err)
	}
	defer func() {
		s.hub.unregister(context.WithoutCancel(ctx), sess)
		s.registry.Forget(id.NodeID)
		s.logger.InfoContext(ctx, "agent disconnected", "node", id.Name)
	}()

	if err := stream.Send(&agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_Accepted{Accepted: &agentv1.ConnectAccepted{
		NodeId: id.NodeID.String(), HeartbeatInterval: durationpb.New(s.registry.HeartbeatInterval()),
	}}}); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "agent connected", "node", id.Name, "node_id", id.NodeID.String(), "instance", s.hub.Instance())

	// A second goroutine owns Send.
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sess.ctx.Done():
				return
			case m := <-sess.send:
				if err := stream.Send(m); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()

	for {
		select {
		case <-sess.ctx.Done():
			return sessionEndStatus(context.Cause(sess.ctx))
		case err := <-recvErr:
			return status.Convert(err).Err()
		case err := <-sendErr:
			return status.Convert(err).Err()
		case m := <-msgs:
			if err := s.handleMessage(ctx, id, sess, m); err != nil {
				return err
			}
		}
	}
}

func awaitHello(ctx context.Context, msgs <-chan *agentv1.ConnectRequest, recvErr <-chan error) (*agentv1.Hello, error) {
	timer := time.NewTimer(helloTimeout)
	defer timer.Stop()
	select {
	case m := <-msgs:
		if h := m.GetHello(); h != nil {
			return h, nil
		}
		return nil, status.Error(codes.InvalidArgument, "the first message on a stream must be a Hello")
	case err := <-recvErr:
		return nil, status.Convert(err).Err()
	case <-timer.C:
		return nil, status.Error(codes.DeadlineExceeded, "no Hello received")
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

func (s *Server) handleMessage(ctx context.Context, id nodes.Identity, sess *session, m *agentv1.ConnectRequest) error {
	switch msg := m.GetMessage().(type) {
	case *agentv1.ConnectRequest_Heartbeat:
		hb := msg.Heartbeat
		sample := &nodes.Sample{
			MemoryAvailableBytes: max(hb.GetMemoryAvailableBytes(), 0), CPULoad1m: max(hb.GetCpuLoad_1M(), 0),
			DiskFreeBytes: max(hb.GetDiskFreeBytes(), 0), RunningContainers: max(hb.GetRunningContainers(), 0),
			AgentVersion: truncate(hb.GetAgentVersion(), 64), Uptime: hb.GetUptime().AsDuration(),
			DockerReachable: hb.GetDockerReachable(),
		}
		if err := s.registry.RecordHeartbeat(ctx, id.NodeID, sample); err != nil {
			return s.toStatus(ctx, err)
		}
		if err := s.hub.touch(ctx, id.NodeID); err != nil {
			return s.toStatus(ctx, err)
		}
	case *agentv1.ConnectRequest_CommandResult:
		s.hub.complete(ctx, sess, msg.CommandResult)
	default:
		return status.Error(codes.InvalidArgument, "unexpected message on the stream")
	}
	return nil
}

// sessionEndStatus explains to the agent why the control plane ended its stream.
func sessionEndStatus(cause error) error {
	switch {
	case errors.Is(cause, nodes.ErrNodeRemoved):
		return status.Error(codes.PermissionDenied, "this node has been removed from Nook; join it again with a new token")
	case errors.Is(cause, errReplaced):
		return status.Error(codes.Aborted, "replaced by a newer connection from this node")
	case errors.Is(cause, errShuttingDown):
		return status.Error(codes.Unavailable, "the control-plane instance is shutting down; reconnect")
	default:
		return status.Error(codes.Canceled, "stream closed")
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
