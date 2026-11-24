package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/version"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// joinTimeout bounds the whole join exchange.
const joinTimeout = 30 * time.Second

// JoinOptions are the inputs of `nook-agent join`.
type JoinOptions struct {
	Server   string // host:port of the control plane's gRPC endpoint
	Token    string
	CAHash   string // sha256:<hex> of the CA certificate
	Name     string
	Labels   map[string]string
	StateDir string
}

// JoinResult describes the node that joined.
type JoinResult struct {
	NodeID string
	Name   string
}

// Join enrolls this machine. It generates the node's private key locally
// and sends only a CSR. Before the join token is sent, the TLS handshake
// must prove that the server holds a certificate from the CA whose
// fingerprint the administrator gave us, so the token cannot be phished
// by an impostor server.
func Join(ctx context.Context, opts *JoinOptions, logger *slog.Logger) (JoinResult, error) {
	dir := stateDir(opts.StateDir)
	if dir.joined() {
		return JoinResult{}, fmt.Errorf("%s already holds a node identity; remove it first to join again", opts.StateDir)
	}
	if err := dir.ensure(); err != nil {
		return JoinResult{}, err
	}
	host, _, err := net.SplitHostPort(opts.Server)
	if err != nil || host == "" {
		return JoinResult{}, fmt.Errorf("--server must be host:port, got %q", opts.Server)
	}
	tlsCfg, err := pki.PinnedTLSConfig(opts.CAHash, host)
	if err != nil {
		return JoinResult{}, err
	}
	key, csr, err := newKeyAndCSR()
	if err != nil {
		return JoinResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, joinTimeout)
	defer cancel()
	conn, err := grpc.NewClient(opts.Server, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return JoinResult{}, fmt.Errorf("connect to %s: %w", opts.Server, err)
	}
	defer func() { _ = conn.Close() }()

	// Docker is optional at join time; the version is reported once known.
	d, dockerErr := newDocker()
	if dockerErr == nil {
		defer func() { _ = d.close() }()
	} else {
		d = nil
	}
	info := newCollector(d).nodeInfo(ctx)
	resp, err := agentv1.NewNodeServiceClient(conn).Join(ctx, &agentv1.JoinRequest{
		JoinToken: opts.Token, CsrDer: csr, Name: opts.Name, Labels: opts.Labels, Info: info,
	}, grpc.WaitForReady(false))
	if err != nil {
		if isCAMismatch(err) {
			return JoinResult{}, fmt.Errorf("refusing to join %s: its certificate authority does not match --ca-hash; the token was not sent", opts.Server)
		}
		return JoinResult{}, fmt.Errorf("join: %w", describeRPCError(err))
	}

	ca, err := x509.ParseCertificate(resp.GetCaCertificateDer())
	if err != nil || pki.Fingerprint(ca.Raw) != opts.CAHash {
		return JoinResult{}, errors.New("the server returned a CA certificate that does not match --ca-hash")
	}
	cert, err := x509.ParseCertificate(resp.GetCertificateDer())
	if err != nil {
		return JoinResult{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	if err := dir.save(&identity{NodeID: resp.GetNodeId(), Name: resp.GetName(), Server: opts.Server, cert: cert, key: key, ca: ca}); err != nil {
		return JoinResult{}, err
	}
	logger.InfoContext(ctx, "joined", "node", resp.GetName(), "node_id", resp.GetNodeId(),
		"certificate_expires", cert.NotAfter.Format(time.RFC3339), "agent_version", version.Get().Version)
	return JoinResult{NodeID: resp.GetNodeId(), Name: resp.GetName()}, nil
}

// newKeyAndCSR generates a P-256 key and a CSR for it. The CSR's subject
// is irrelevant: the control plane assigns the identity.
func newKeyAndCSR() (crypto.Signer, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate node key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nook-node"}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	return key, csr, nil
}
