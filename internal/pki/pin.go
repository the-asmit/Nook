package pki

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
)

// fingerprintPattern matches a --ca-hash value.
var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ErrCAMismatch means the server presented a CA other than the pinned one.
var ErrCAMismatch = errors.New("the server's CA does not match --ca-hash")

// ValidFingerprint reports whether s has the form sha256:<64 hex digits>.
func ValidFingerprint(s string) bool {
	return fingerprintPattern.MatchString(s)
}

// PinnedTLSConfig returns a client TLS configuration for joining: before
// anything is sent, the handshake fails unless the server's chain contains
// the CA with the pinned fingerprint and that CA signed a certificate valid
// for serverName. This is how an agent that does not yet trust any CA
// avoids handing its join token to an impostor.
func PinnedTLSConfig(fingerprint, serverName string) (*tls.Config, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, fmt.Errorf("--ca-hash must look like sha256:<64 hex digits>, got %q", fingerprint)
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// Standard verification needs a trusted root, which a joining agent
		// does not have yet; VerifyConnection performs the equivalent check
		// against the pinned CA instead.
		InsecureSkipVerify: true, //nolint:gosec // G402: replaced by the pinned verification below.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinned(cs.PeerCertificates, fingerprint, serverName)
		},
	}
	return cfg, nil
}

func verifyPinned(chain []*x509.Certificate, fingerprint, serverName string) error {
	if len(chain) < 2 {
		return fmt.Errorf("%w: server sent no CA certificate", ErrCAMismatch)
	}
	var ca *x509.Certificate
	for _, c := range chain[1:] {
		if subtle.ConstantTimeCompare([]byte(Fingerprint(c.Raw)), []byte(fingerprint)) == 1 && c.IsCA {
			ca = c
		}
	}
	if ca == nil {
		return ErrCAMismatch
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: pool, DNSName: serverName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("server certificate is not valid for %s under the pinned CA: %w", serverName, err)
	}
	return nil
}
