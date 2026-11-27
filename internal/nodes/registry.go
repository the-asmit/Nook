package nodes

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/store"
)

// Authentication failures. They are distinguished in logs, but agents
// only learn that their credentials are no longer accepted.
var (
	ErrUnknownCertificate = errors.New("certificate was not issued to a known node")
	ErrCertificateRevoked = errors.New("certificate has been revoked")
	ErrNodeRemoved        = errors.New("node has been removed")
)

// Identity is an authenticated agent connection.
type Identity struct {
	NodeID uuid.UUID
	Name   string
	Serial string
}

// Registry joins nodes, authenticates their certificates and records
// their heartbeats.
type Registry struct {
	store      *store.Store
	ca         *pki.CA
	heartbeats *Heartbeats
	publisher  *Publisher
	cfg        Config
	logger     *slog.Logger

	mu        sync.Mutex
	persisted map[uuid.UUID]time.Time
}

// NewRegistry returns a node registry.
func NewRegistry(st *store.Store, ca *pki.CA, hb *Heartbeats, pub *Publisher, cfg Config, logger *slog.Logger) *Registry {
	return &Registry{store: st, ca: ca, heartbeats: hb, publisher: pub, cfg: cfg, logger: logger, persisted: map[uuid.UUID]time.Time{}}
}

// JoinRequest is a validated join attempt.
type JoinRequest struct {
	Token  string
	CSR    []byte
	Name   string
	Labels map[string]string
	Info   Info
	IP     *netip.Addr
}

// Joined is a successful join.
type Joined struct {
	Node store.Node
	Cert pki.IssuedCert
}

// errBadJoinToken is deliberately vague: unknown, expired, revoked and
// used-up tokens all look the same to the caller.
func errBadJoinToken() error {
	return apperr.Unauthenticated("the join token is invalid, expired, revoked or already used")
}

// Join consumes a join token and creates the node with its first
// certificate, in one transaction: if anything fails, the token use is
// rolled back too.
func (r *Registry) Join(ctx context.Context, req *JoinRequest) (Joined, error) {
	if !LooksLikeJoinToken(req.Token) {
		return Joined{}, errBadJoinToken()
	}
	name, err := normalizeNodeName(req.Name, req.Info.Hostname)
	if err != nil {
		return Joined{}, err
	}
	labels, err := encodeLabels(req.Labels)
	if err != nil {
		return Joined{}, err
	}
	info := req.Info.sanitized()

	var res Joined
	var ev *Event
	txErr := r.store.InTx(ctx, func(q *store.Queries) error {
		tokenID, err := q.ConsumeJoinToken(ctx, auth.Hash(req.Token))
		if store.IsNotFound(err) {
			return errBadJoinToken()
		}
		if err != nil {
			return fmt.Errorf("consume join token: %w", err)
		}
		node, err := q.CreateNode(ctx, store.CreateNodeParams{
			Name: name, Labels: labels, Hostname: info.Hostname, Addresses: info.Addresses,
			CpuCount: info.CPUCount, MemoryTotalBytes: info.MemoryTotalBytes, DiskTotalBytes: info.DiskTotalBytes,
			DockerVersion: info.DockerVersion, AgentVersion: info.AgentVersion, Os: info.OS, Arch: info.Arch,
			JoinedWithTokenID: &tokenID,
		})
		if err != nil {
			return fmt.Errorf("create node: %w", err)
		}
		cert, err := r.issue(ctx, q, node.ID, req.CSR)
		if err != nil {
			return err
		}
		ev, err = recordTransition(ctx, q, node.ID, node.Name, nil, store.NodeStatusJoining, "joined")
		if err != nil {
			return err
		}
		res = Joined{Node: node, Cert: cert}
		return audit.Record(ctx, q, &audit.Entry{
			IP: req.IP, Action: audit.ActionNodeJoin, TargetType: audit.TargetNode, TargetID: node.ID.String(),
			Metadata: map[string]any{"name": node.Name, "join_token_id": tokenID.String(), "hostname": info.Hostname},
		})
	})
	if store.IsUniqueViolation(txErr, "nodes_name_active_key") {
		return Joined{}, apperr.Conflict("node_name_taken", "a node named %q already exists; choose another --name", name)
	}
	if txErr != nil {
		return Joined{}, txErr
	}
	r.publish(ctx, ev)
	return res, nil
}

// issue signs a CSR for nodeID and records the certificate serial.
func (r *Registry) issue(ctx context.Context, q *store.Queries, nodeID uuid.UUID, csr []byte) (pki.IssuedCert, error) {
	cert, err := r.ca.SignNodeCSR(csr, nodeID, r.cfg.CertTTL)
	if errors.Is(err, pki.ErrBadCSR) {
		return pki.IssuedCert{}, apperr.Invalid("invalid_csr", "%v", err)
	}
	if err != nil {
		return pki.IssuedCert{}, err
	}
	err = q.InsertNodeCertificate(ctx, store.InsertNodeCertificateParams{
		Serial: pki.SerialHex(cert.Cert), NodeID: nodeID, NotBefore: cert.Cert.NotBefore, NotAfter: cert.Cert.NotAfter,
	})
	if err != nil {
		return pki.IssuedCert{}, fmt.Errorf("record certificate: %w", err)
	}
	return cert, nil
}

// Authenticate checks a verified client certificate against the database:
// it must be on record for its node, not revoked, and the node not removed.
// TLS has already checked the signature and validity period.
func (r *Registry) Authenticate(ctx context.Context, cert *x509.Certificate) (Identity, error) {
	nodeID, err := pki.NodeID(cert)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrUnknownCertificate, err)
	}
	row, err := r.store.GetNodeCertificate(ctx, pki.SerialHex(cert))
	if store.IsNotFound(err) {
		return Identity{}, ErrUnknownCertificate
	}
	if err != nil {
		return Identity{}, fmt.Errorf("look up certificate: %w", err)
	}
	switch {
	case row.NodeID != nodeID:
		return Identity{}, ErrUnknownCertificate
	case row.NodeStatus == store.NodeStatusRemoved:
		return Identity{}, ErrNodeRemoved
	case row.RevokedAt != nil:
		return Identity{}, ErrCertificateRevoked
	}
	return Identity{NodeID: nodeID, Name: row.NodeName, Serial: row.Serial}, nil
}

// Renew issues a new certificate for an authenticated node and revokes the
// one it authenticated with.
func (r *Registry) Renew(ctx context.Context, id Identity, csr []byte) (pki.IssuedCert, error) {
	var cert pki.IssuedCert
	err := r.store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.LockLiveNode(ctx, id.NodeID); store.IsNotFound(err) {
			return ErrNodeRemoved
		} else if err != nil {
			return fmt.Errorf("lock node: %w", err)
		}
		var err error
		cert, err = r.issue(ctx, q, id.NodeID, csr)
		if err != nil {
			return err
		}
		if _, err := q.RevokeNodeCertificate(ctx, id.Serial); err != nil {
			return fmt.Errorf("revoke previous certificate: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			Action: audit.ActionNodeCertRenew, TargetType: audit.TargetNode, TargetID: id.NodeID.String(),
			Metadata: map[string]any{"name": id.Name, "old_serial": id.Serial, "new_serial": pki.SerialHex(cert.Cert),
				"not_after": cert.Cert.NotAfter},
		})
	})
	return cert, err
}

// UpdateInfo stores what an agent reports about itself when it connects.
func (r *Registry) UpdateInfo(ctx context.Context, nodeID uuid.UUID, info *Info) error {
	i := info.sanitized()
	err := r.store.UpdateNodeInfo(ctx, store.UpdateNodeInfoParams{
		ID: nodeID, Hostname: i.Hostname, Addresses: i.Addresses, CpuCount: i.CPUCount,
		MemoryTotalBytes: i.MemoryTotalBytes, DiskTotalBytes: i.DiskTotalBytes,
		DockerVersion: i.DockerVersion, AgentVersion: i.AgentVersion, Os: i.OS, Arch: i.Arch,
		BuildSlots: i.BuildSlots, AdvertiseAddress: i.AdvertiseAddress, BuildsUnavailableReason: i.BuildsUnavailableReason,
		DbAddress: i.DatabaseAddress, DbPublishAddress: i.DatabasePublishAddress, DbPort: i.DatabasePort,
		DbUnavailableReason: i.DatabaseUnavailableReason,
	})
	if err != nil {
		return fmt.Errorf("update node info: %w", err)
	}
	return nil
}

// RecordHeartbeat stores a heartbeat in Redis (always) and in Postgres (at
// most once per PersistInterval per node on this instance).
func (r *Registry) RecordHeartbeat(ctx context.Context, nodeID uuid.UUID, s *Sample) error {
	if err := r.heartbeats.Record(ctx, nodeID, s); err != nil {
		return err
	}
	r.mu.Lock()
	last, ok := r.persisted[nodeID]
	due := !ok || s.ReceivedAt.Sub(last) >= r.cfg.PersistInterval
	if due {
		r.persisted[nodeID] = s.ReceivedAt
	}
	r.mu.Unlock()
	if !due {
		return nil
	}
	err := r.store.PersistHeartbeat(ctx, store.PersistHeartbeatParams{
		ID: nodeID, ReceivedAt: &s.ReceivedAt, MemoryAvailableBytes: &s.MemoryAvailableBytes, CpuLoad1m: &s.CPULoad1m,
		DiskFreeBytes: &s.DiskFreeBytes, RunningContainers: &s.RunningContainers, DockerReachable: &s.DockerReachable,
		AgentVersion: s.AgentVersion,
	})
	if err != nil {
		return fmt.Errorf("persist heartbeat: %w", err)
	}
	return nil
}

// Forget drops per-node state kept on this instance when a stream ends.
func (r *Registry) Forget(nodeID uuid.UUID) {
	r.mu.Lock()
	delete(r.persisted, nodeID)
	r.mu.Unlock()
}

// CommandTimeout is the default timeout for commands sent to agents.
func (r *Registry) CommandTimeout() time.Duration {
	return r.cfg.CommandTimeout
}

// HeartbeatInterval tells agents how often to send heartbeats.
func (r *Registry) HeartbeatInterval() time.Duration {
	return r.cfg.HeartbeatInterval
}

func (r *Registry) publish(ctx context.Context, ev *Event) {
	if ev == nil {
		return
	}
	if err := r.publisher.Event(ctx, ev); err != nil {
		r.logger.WarnContext(ctx, "publish node event", "error", err.Error())
	}
}
