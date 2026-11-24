package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
	"uuid"
)

// nodeURIPrefix forms the URI SAN that carries a node's identity.
const nodeURIPrefix = "urn:nook:node:"

// clockSkew backdates NotBefore so that a peer whose clock is slightly
// behind still accepts a fresh certificate.
const clockSkew = 5 * time.Minute

// ErrBadCSR means a certificate signing request is malformed or uses a
// key type Nook does not accept.
var ErrBadCSR = errors.New("invalid certificate signing request")

// IssuedCert is a node certificate signed by the CA.
type IssuedCert struct {
	DER  []byte
	Cert *x509.Certificate
}

// SignNodeCSR issues a client certificate for nodeID from a CSR. The
// subject requested in the CSR is ignored: identity comes only from the
// node ID the control plane assigned.
func (ca *CA) SignNodeCSR(csrDER []byte, nodeID uuid.UUID, ttl time.Duration) (IssuedCert, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("%w: %w", ErrBadCSR, err)
	}
	if err = csr.CheckSignature(); err != nil {
		return IssuedCert{}, fmt.Errorf("%w: bad signature", ErrBadCSR)
	}
	if !acceptableKey(csr.PublicKey) {
		return IssuedCert{}, fmt.Errorf("%w: key must be ECDSA P-256 or Ed25519", ErrBadCSR)
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID.String(), Organization: []string{"Nook nodes"}},
		URIs:         []*url.URL{{Scheme: "urn", Opaque: "nook:node:" + nodeID.String()}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("sign node certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	return IssuedCert{DER: der, Cert: cert}, nil
}

func acceptableKey(k any) bool {
	switch key := k.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return true
	default:
		return false
	}
}

// NodeID extracts the node identity from a certificate this CA issued.
func NodeID(c *x509.Certificate) (uuid.UUID, error) {
	for _, u := range c.URIs {
		if s := u.String(); strings.HasPrefix(s, nodeURIPrefix) {
			id, err := uuid.Parse(strings.TrimPrefix(s, nodeURIPrefix))
			if err != nil {
				return uuid.UUID{}, fmt.Errorf("malformed node URI %q", s)
			}
			return id, nil
		}
	}
	return uuid.UUID{}, errors.New("certificate carries no node identity")
}

// ServerCerts issues and rotates the gRPC server certificate. Each
// control-plane instance issues its own from the shared CA, so no server
// key has to be distributed.
type ServerCerts struct {
	ca    *CA
	names []string
	ttl   time.Duration

	mu      sync.Mutex
	current *tls.Certificate
	expiry  time.Time
}

// NewServerCerts returns a rotating source of server certificates valid
// for names (host names and IP addresses).
func NewServerCerts(ca *CA, names []string, ttl time.Duration) (*ServerCerts, error) {
	if len(names) == 0 {
		return nil, errors.New("the server certificate needs at least one name")
	}
	s := &ServerCerts{ca: ca, names: names, ttl: ttl}
	if _, err := s.get(); err != nil {
		return nil, err
	}
	return s, nil
}

// GetCertificate implements tls.Config.GetCertificate. A new certificate
// is issued once two thirds of the current one's lifetime has passed.
func (s *ServerCerts) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.get()
}

func (s *ServerCerts) get() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && time.Until(s.expiry) > s.ttl/3 {
		return s.current, nil
	}
	cert, expiry, err := s.ca.issueServer(s.names, s.ttl)
	if err != nil {
		return nil, err
	}
	s.current, s.expiry = cert, expiry
	return cert, nil
}

func (ca *CA) issueServer(names []string, ttl time.Duration) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"Nook control plane"}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse server certificate: %w", err)
	}
	// The chain includes the CA so joining agents can pin it by fingerprint.
	return &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, tmpl.NotAfter, nil
}
