package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/the-asmit/nook/internal/pki"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// renewTimeout bounds one renewal exchange.
const renewTimeout = 30 * time.Second

// renewDue reports whether a certificate should be renewed: once two thirds
// of its lifetime has passed, which for 7-day certificates leaves more than
// two days to retry if the control plane is unreachable.
func renewDue(c *x509.Certificate, now time.Time) bool {
	lifetime := c.NotAfter.Sub(c.NotBefore)
	return now.After(c.NotBefore.Add(lifetime * 2 / 3))
}

// renewLoop checks the certificate periodically and renews it when due.
// It returns only on a permanent rejection (or when ctx ends).
func (a *Agent) renewLoop(ctx context.Context) error {
	ticker := time.NewTicker(a.cfg.RenewCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if !renewDue(a.id.Load().cert, time.Now()) {
			continue
		}
		if err := a.Renew(ctx); err != nil {
			if permanent(err) {
				return fmt.Errorf("certificate renewal rejected: %w", describeRPCError(err))
			}
			a.logger.WarnContext(ctx, "certificate renewal failed; will retry", "error", err.Error(),
				"expires", a.id.Load().cert.NotAfter.Format(time.RFC3339))
		}
	}
}

// Renew obtains a certificate for a freshly generated key, stores it and
// makes the next connection use it. The new key never leaves the node.
func (a *Agent) Renew(ctx context.Context) error {
	key, csr, err := newKeyAndCSR()
	if err != nil {
		return err
	}
	conn, err := a.dial()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, renewTimeout)
	defer cancel()
	resp, err := agentv1.NewNodeServiceClient(conn).RenewCertificate(ctx, &agentv1.RenewCertificateRequest{CsrDer: csr})
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(resp.GetCertificateDer())
	if err != nil {
		return fmt.Errorf("parse renewed certificate: %w", err)
	}
	if !pki.SamePublicKey(cert.PublicKey, key.Public()) {
		return errors.New("renewed certificate does not match the generated key")
	}
	if err := a.dir.saveCertificate(cert.Raw, key); err != nil {
		return err
	}
	current := a.id.Load()
	next := *current
	next.cert, next.key = cert, key
	a.id.Store(&next)
	a.metrics.certExpiry.Set(float64(cert.NotAfter.Unix()))
	a.logger.InfoContext(ctx, "certificate renewed", "expires", cert.NotAfter.Format(time.RFC3339))
	// The current connection was authenticated with the old (now revoked)
	// certificate; reconnect so the control plane sees the new one.
	select {
	case a.reconnect <- struct{}{}:
	default:
	}
	return nil
}
