package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// startServer runs Serve in the background and returns its result channel.
func startServer(t *testing.T, ctx context.Context, cfg *Config, h http.Handler) (*Server, <-chan error) {
	t.Helper()
	srv, err := Listen(ctx, cfg, h, discardLogger)
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	return srv, done
}

func waitResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for result")
		return nil
	}
}

// waitUntilRefused polls until new connections to addr are refused, which
// shows the listener has closed. It polls with a deadline instead of sleeping.
func waitUntilRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: 100 * time.Millisecond}
		conn, err := d.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			return
		}
		_ = conn.Close()
	}
	t.Fatal("listener still accepting connections")
}

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func TestServeDrainsInFlightRequestsOnShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "finished")
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, done := startServer(t, ctx, new(validConfig()), h)
	addr := srv.Addr().String()

	type result struct {
		body string
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := get(context.Background(), http.DefaultClient, "http://"+addr+"/")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		resCh <- result{body: string(b), err: err}
	}()

	<-started
	cancel() // like SIGTERM
	waitUntilRefused(t, addr)

	close(release)
	res := <-resCh
	if res.err != nil || res.body != "finished" {
		t.Fatalf("in-flight request: body %q err %v", res.body, res.err)
	}
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Serve() = %v, want clean shutdown", err)
	}
}

func TestServeForcesCloseAfterShutdownTimeout(t *testing.T) {
	started := make(chan struct{})
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done() // never finishes on its own
	})
	cfg := validConfig()
	cfg.ShutdownTimeout = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	srv, done := startServer(t, ctx, &cfg, h)
	clientErr := make(chan error, 1)
	go func() {
		resp, err := get(context.Background(), http.DefaultClient, "http://"+srv.Addr().String()+"/")
		if err == nil {
			_ = resp.Body.Close()
		}
		clientErr <- err
	}()

	<-started
	cancel()
	err := waitResult(t, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve() = %v, want deadline exceeded", err)
	}
	if err := waitResult(t, clientErr); err == nil {
		t.Fatal("client should see its connection closed")
	}
}

func TestListenFailsWhenAddressInUse(t *testing.T) {
	ctx := context.Background()
	srv, err := Listen(ctx, new(validConfig()), http.NotFoundHandler(), discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.listener.Close() }()

	cfg := validConfig()
	cfg.Addr = srv.Addr().String()
	if _, err := Listen(ctx, &cfg, http.NotFoundHandler(), discardLogger); err == nil {
		t.Fatal("second Listen on the same address should fail")
	}
}

func TestServeReportsUnexpectedStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := Listen(ctx, new(validConfig()), http.NotFoundHandler(), discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	_ = srv.listener.Close() // simulate the listener dying underneath the server
	if err := srv.Serve(ctx); err == nil {
		t.Fatal("Serve() should report the failure")
	}
}

func writeSelfSignedCert(t *testing.T) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certPath, keyPath, pool
}

func TestServeTLS(t *testing.T) {
	certPath, keyPath, roots := writeSelfSignedCert(t)
	cfg := validConfig()
	cfg.TLSCertPath, cfg.TLSKeyPath = certPath, keyPath

	ctx, cancel := context.WithCancel(context.Background())
	srv, done := startServer(t, ctx, &cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			w.WriteHeader(http.StatusTeapot)
		}
	}))

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	resp, err := get(context.Background(), client, "https://"+srv.Addr().String()+"/")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 over TLS 1.3", resp.StatusCode)
	}

	// A deliberately outdated client, to prove the server refuses it.
	tls12 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MaxVersion: tls.VersionTLS12}}} //nolint:gosec // G402 is the point of this test.
	if resp, err := get(context.Background(), tls12, "https://"+srv.Addr().String()+"/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("TLS 1.2 client should be rejected")
	}

	cancel()
	if err := waitResult(t, done); err != nil {
		t.Fatalf("Serve() = %v", err)
	}
}

func TestListenRejectsUnreadableCertificate(t *testing.T) {
	cfg := validConfig()
	cfg.TLSCertPath, cfg.TLSKeyPath = filepath.Join(t.TempDir(), "missing.pem"), "missing-key.pem"
	if _, err := Listen(context.Background(), &cfg, http.NotFoundHandler(), discardLogger); err == nil {
		t.Fatal("Listen() should fail with missing certificate files")
	}
}
