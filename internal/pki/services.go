package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Certificates for the other services of a Nook installation (the image
// registry), issued from the same internal CA that signs node identities.

// IssueServerCertificate issues a TLS server certificate for names (DNS
// names or IP addresses). The chain includes the CA certificate.
func (ca *CA) IssueServerCertificate(names []string, ttl time.Duration) (*tls.Certificate, error) {
	if len(names) == 0 {
		return nil, errors.New("at least one name is required")
	}
	cert, _, err := ca.issueServer(names, ttl)
	return cert, err
}

// Signer is a key with a certificate the CA issued for signing tokens.
type Signer struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
}

// IssueSigner issues a certificate for a fresh ECDSA P-256 key that may
// only sign (no TLS usage), named commonName. The registry trusts tokens
// whose signing certificate chains to the CA.
func (ca *CA) IssueSigner(commonName string, ttl time.Duration) (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Nook control plane"}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse signing certificate: %w", err)
	}
	return &Signer{Key: key, Cert: cert}, nil
}

// WriteServerFiles writes a server certificate as dir/tls.crt (leaf and
// chain), dir/tls.key (mode 0600) and the CA certificate as dir/ca.crt,
// the layout the registry container mounts.
func (ca *CA) WriteServerFiles(dir string, cert *tls.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	var chain []byte
	for _, der := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("encode key: %w", err)
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"tls.crt", chain, 0o644},
		{"tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600},
		{"ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o644},
	}
	for _, f := range files {
		if err := writeFileAtomic(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// CertificatePEM returns the CA certificate in PEM form.
func (ca *CA) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
