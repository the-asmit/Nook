package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newUpgradeEcho is an upstream that accepts any upgrade and echoes bytes.
func newUpgradeEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		buf := make([]byte, 4096)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// upgradedConn is a client connection after a 101 response.
type upgradedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// dialUpgrade opens an upgraded connection to host through the gateway.
func dialUpgrade(t *testing.T, addr, host string) *upgradedConn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET /ws HTTP/1.1\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, werr := io.WriteString(conn, req); werr != nil {
		t.Fatal(werr)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close() // a 101 response has no body
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", resp.StatusCode)
	}
	return &upgradedConn{Conn: conn, r: br}
}

// echo sends msg and expects it back.
func echo(t *testing.T, c io.ReadWriter, msg string) {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	return testutil.ToFloat64(g)
}

func TestConnTrackerWaitsThenCloses(t *testing.T) {
	m, err := newMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	tr := newConnTracker()
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	tracked := tr.track(a, m)

	// Closed by its owner before the deadline: wait returns 0.
	done := make(chan int, 1)
	go func() { done <- tr.wait(t.Context()) }()
	_ = tracked.Close()
	if n := <-done; n != 0 {
		t.Fatalf("wait = %d after the connection closed itself", n)
	}

	// Still open at the deadline: closed by wait.
	c, d := net.Pipe()
	defer func() { _ = d.Close() }()
	tr.track(c, m)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if n := tr.wait(ctx); n != 1 {
		t.Fatalf("wait = %d at the deadline, want 1", n)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("the connection is still open after the drain deadline")
	}
	if v := gaugeValue(t, m.upgraded); v != 0 {
		t.Fatalf("upgraded gauge = %v, want 0", v)
	}
}
