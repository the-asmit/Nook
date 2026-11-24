package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"
)

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pki", "ca.pem")
	ca, created, err := LoadOrCreateCA(path)
	if err != nil || !created {
		t.Fatalf("LoadOrCreateCA = %v, created %v", err, created)
	}
	return ca, path
}

func TestCAIsCreatedOnceAndReloaded(t *testing.T) {
	ca, path := newCA(t)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("CA file mode %v, %v", info.Mode().Perm(), err)
	}
	if dir, _ := os.Stat(filepath.Dir(path)); dir.Mode().Perm() != 0o700 {
		t.Fatalf("CA dir mode %v", dir.Mode().Perm())
	}
	again, created, err := LoadOrCreateCA(path)
	if err != nil || created || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload: created %v err %v", created, err)
	}
	c := ca.Certificate()
	if !c.IsCA || !c.MaxPathLenZero || c.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("CA certificate %+v", c)
	}
	if !ValidFingerprint(ca.Fingerprint()) {
		t.Fatalf("fingerprint %q", ca.Fingerprint())
	}
}

func TestCARefusesLoosePermissions(t *testing.T) {
	_, path := newCA(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCA(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("err = %v, want ErrInsecurePermissions", err)
	}
}

func TestConcurrentCreationYieldsOneCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	const n = 8
	prints := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			ca, _, err := LoadOrCreateCA(path)
			if err != nil {
				t.Error(err)
				return
			}
			prints[i] = ca.Fingerprint()
		})
	}
	wg.Wait()
	for _, p := range prints {
		if p != prints[0] {
			t.Fatalf("instances ended up with different CAs: %v", prints)
		}
	}
}

func TestCARejectsCorruptBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateCA(path); err == nil {
		t.Fatal("corrupt bundle accepted")
	}
}

func csrFor(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil-admin"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignNodeCSR(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := uuid.NewV7()
	issued, err := ca.SignNodeCSR(csrFor(t, key), id, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := issued.Cert
	got, err := NodeID(c)
	if err != nil || got != id || c.Subject.CommonName != id.String() {
		t.Fatalf("identity = %v %v, CN %q (the CSR subject must be ignored)", got, err, c.Subject.CommonName)
	}
	if c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || c.IsCA {
		t.Fatal("node certificate must be a client-auth leaf")
	}
	if d := time.Until(c.NotAfter); d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour+time.Minute {
		t.Fatalf("validity %s", d)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued certificate does not verify: %v", err)
	}
	if SerialHex(c) == "" || len(SerialHex(c)) > 40 {
		t.Fatalf("serial %q", SerialHex(c))
	}
}

func TestSignNodeCSRRejectsBadInput(t *testing.T) {
	ca, _ := newCA(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tampered := csrFor(t, good)
	tampered[len(tampered)-5] ^= 0xff
	for name, csr := range map[string][]byte{
		"garbage": []byte("nope"), "rsa": csrFor(t, rsaKey), "p384": csrFor(t, p384), "bad signature": tampered,
	} {
		if _, err := ca.SignNodeCSR(csr, uuid.NewV7(), time.Hour); !errors.Is(err, ErrBadCSR) {
			t.Errorf("%s: err = %v, want ErrBadCSR", name, err)
		}
	}
}

func TestNodeIDRequiresNookURI(t *testing.T) {
	if _, err := NodeID(&x509.Certificate{}); err == nil {
		t.Fatal("certificate without URI accepted")
	}
}

// serveTLS runs a TLS server presenting certs and reports handshake errors.
func serveTLS(t *testing.T, certs *ServerCerts) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: certs.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tc, ok := conn.(*tls.Conn); ok {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = tc.HandshakeContext(ctx)
					cancel()
				}
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func dialPinned(t *testing.T, addr, fingerprint, serverName string) error {
	t.Helper()
	cfg, err := PinnedTLSConfig(fingerprint, serverName)
	if err != nil {
		return err
	}
	d := tls.Dialer{Config: cfg, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func TestPinnedTLS(t *testing.T) {
	ca, _ := newCA(t)
	certs, err := NewServerCerts(ca, []string{"127.0.0.1", "nook.internal"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, certs)
	if err := dialPinned(t, addr, ca.Fingerprint(), "127.0.0.1"); err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	other, _ := newCA(t)
	if err := dialPinned(t, addr, other.Fingerprint(), "127.0.0.1"); err == nil || !strings.Contains(err.Error(), ErrCAMismatch.Error()) {
		t.Fatalf("foreign pin: err = %v", err)
	}
	if err := dialPinned(t, addr, ca.Fingerprint(), "evil.example"); err == nil {
		t.Fatal("certificate accepted for a name it does not cover")
	}
	if _, err := PinnedTLSConfig("md5:abc", "x"); err == nil {
		t.Fatal("malformed fingerprint accepted")
	}
}

func TestServerCertificateCoversNames(t *testing.T) {
	ca, _ := newCA(t)
	certs, err := NewServerCerts(ca, []string{"nook.example.com", "10.0.0.5"}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := certs.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Certificate) != 2 || Fingerprint(c.Certificate[1]) != ca.Fingerprint() {
		t.Fatal("chain must include the CA for pinning")
	}
	for _, name := range []string{"nook.example.com", "10.0.0.5"} {
		if err := c.Leaf.VerifyHostname(name); err != nil {
			t.Errorf("%s not covered: %v", name, err)
		}
	}
	again, _ := certs.GetCertificate(nil)
	if again != c {
		t.Fatal("certificate re-issued although still fresh")
	}
	if _, err := NewServerCerts(ca, nil, time.Hour); err == nil {
		t.Fatal("no names accepted")
	}
}

func TestKeyPairRoundTrip(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issued, _ := ca.SignNodeCSR(csrFor(t, key), uuid.NewV7(), time.Hour)
	pem, err := EncodeKeyPair(issued.DER, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, k, err := ParseKeyPair(pem)
	if err != nil || !SamePublicKey(cert.PublicKey, k.Public()) {
		t.Fatalf("round trip: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mismatched, _ := EncodeKeyPair(issued.DER, other)
	if _, _, err := ParseKeyPair(mismatched); err == nil {
		t.Fatal("mismatched key accepted")
	}
}
