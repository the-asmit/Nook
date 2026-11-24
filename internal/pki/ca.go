// Package pki is the control plane's internal certificate authority for
// agent traffic: it creates or loads the CA, issues the gRPC server
// certificate and short-lived node client certificates from CSRs, and
// implements CA pinning by fingerprint for joining agents.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// caValidity is how long a newly created CA is valid. Node and server
// certificates are short-lived; the CA is the long-lived trust anchor.
const caValidity = 10 * 365 * 24 * time.Hour

// maxFileSize bounds reads of PEM files.
const maxFileSize = 64 << 10

// ErrInsecurePermissions means a key file can be read by other users.
var ErrInsecurePermissions = errors.New("key file permissions are too open")

// CA is a loaded certificate authority.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pool *x509.CertPool
}

// LoadOrCreateCA loads the CA bundle (certificate and private key in one
// PEM file, mode 0600) at path, creating a new CA if the file does not
// exist. It reports whether it created one.
//
// Creation is safe when several control-plane instances share the file
// (for example on a shared volume): the bundle is written to a temporary
// file and hard-linked into place, which fails if another instance won
// the race, in which case that instance's CA is loaded instead.
func LoadOrCreateCA(path string) (*CA, bool, error) {
	ca, err := loadCA(path)
	if err == nil {
		return ca, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	bundle, err := newCABundle()
	if err != nil {
		return nil, false, err
	}
	if err = writeExclusive(path, bundle); err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Another instance won the race; use its CA.
			ca, err = loadCA(path)
			return ca, false, err
		}
		return nil, false, err
	}
	ca, err = loadCA(path)
	return ca, err == nil, err
}

func newCABundle() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Nook internal CA", Organization: []string{"Nook"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Only end-entity certificates below this CA.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode CA key: %w", err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...), nil
}

// writeExclusive writes data to path with mode 0600 unless path exists.
func writeExclusive(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".ca-*.pem")
	if err != nil {
		return fmt.Errorf("write CA: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write CA: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write CA: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write CA: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}
	// link(2) never replaces an existing file, unlike rename(2).
	if err := os.Link(tmp.Name(), path); err != nil {
		return fmt.Errorf("install CA: %w", err)
	}
	return nil
}

// ReadPrivateFile reads a file that holds key material, refusing it if
// anyone but its owner may read or write it (as ssh does for keys).
func ReadPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o, want 0600", ErrInsecurePermissions, path, info.Mode().Perm())
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-configured path.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func loadCA(path string) (*CA, error) {
	data, err := ReadPrivateFile(path)
	if err != nil {
		return nil, err
	}
	cert, key, err := parseBundle(data)
	if err != nil {
		return nil, fmt.Errorf("CA bundle %s: %w", path, err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("CA bundle %s: certificate is not a CA", path)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("CA bundle %s: certificate expired on %s", path, cert.NotAfter.Format(time.DateOnly))
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{cert: cert, key: key, pool: pool}, nil
}

// ParseKeyPair decodes a PEM bundle holding a certificate and the PKCS #8
// private key that matches it.
func ParseKeyPair(data []byte) (*x509.Certificate, crypto.Signer, error) {
	return parseBundle(data)
}

// EncodeKeyPair encodes a DER certificate and its private key as one PEM
// bundle, so both can be replaced together in a single atomic write.
func EncodeKeyPair(certDER []byte, key crypto.Signer) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode key: %w", err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...), nil
}

func parseBundle(data []byte) (*x509.Certificate, crypto.Signer, error) {
	var cert *x509.Certificate
	var key crypto.Signer
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse certificate: %w", err)
			}
			cert = c
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse key: %w", err)
			}
			signer, ok := k.(crypto.Signer)
			if !ok {
				return nil, nil, errors.New("key cannot sign")
			}
			key = signer
		}
	}
	if cert == nil || key == nil {
		return nil, nil, errors.New("must contain a CERTIFICATE and a PRIVATE KEY block")
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, nil, errors.New("private key does not match the certificate")
	}
	return cert, key, nil
}

// SamePublicKey reports whether two public keys are identical.
func SamePublicKey(a, b crypto.PublicKey) bool {
	return publicKeysEqual(a, b)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// Certificate returns the CA certificate.
func (ca *CA) Certificate() *x509.Certificate {
	return ca.cert
}

// Pool returns a pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	return ca.pool
}

// Fingerprint is the value agents pin with --ca-hash.
func (ca *CA) Fingerprint() string {
	return Fingerprint(ca.cert.Raw)
}

// Fingerprint formats the SHA-256 of a DER certificate as "sha256:<hex>".
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// randomSerial returns a positive 128-bit serial number. Random serials
// make certificates unpredictable and unique without coordination.
func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// SerialHex is how serial numbers are stored (lower-case hex).
func SerialHex(c *x509.Certificate) string {
	return c.SerialNumber.Text(16)
}
