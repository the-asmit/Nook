package nodes

import (
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/store"
)

var cfg = Config{
	HeartbeatInterval: 5 * time.Second, DeadAfter: 30 * time.Second, PersistInterval: 30 * time.Second,
	DetectorInterval: time.Second, CertTTL: 168 * time.Hour, JoinTokenTTL: time.Hour, CommandTimeout: 15 * time.Second,
}

func TestDecide(t *testing.T) {
	joined := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := joined.Add(d); return &v }
	cases := []struct {
		name     string
		status   store.NodeStatus
		draining bool
		lastSeen *time.Time
		now      time.Duration
		want     store.NodeStatus
	}{
		{"fresh join, no heartbeat yet", store.NodeStatusJoining, false, nil, 10 * time.Second, store.NodeStatusJoining},
		{"never heartbeated", store.NodeStatusJoining, false, nil, 30 * time.Second, store.NodeStatusDead},
		{"first heartbeat", store.NodeStatusJoining, false, at(time.Second), 2 * time.Second, store.NodeStatusReady},
		{"just under suspect", store.NodeStatusReady, false, at(0), 15*time.Second - time.Millisecond, store.NodeStatusReady},
		{"three missed intervals", store.NodeStatusReady, false, at(0), 15 * time.Second, store.NodeStatusSuspect},
		{"just under dead", store.NodeStatusSuspect, false, at(0), 30*time.Second - time.Millisecond, store.NodeStatusSuspect},
		{"dead threshold", store.NodeStatusSuspect, false, at(0), 30 * time.Second, store.NodeStatusDead},
		{"recovers", store.NodeStatusDead, false, at(time.Minute), time.Minute + time.Second, store.NodeStatusReady},
		{"draining stays draining", store.NodeStatusDraining, true, at(0), time.Second, store.NodeStatusDraining},
		{"draining goes suspect", store.NodeStatusDraining, true, at(0), 20 * time.Second, store.NodeStatusSuspect},
		{"draining recovers to draining", store.NodeStatusDead, true, at(time.Minute), time.Minute + time.Second, store.NodeStatusDraining},
	}
	for _, tc := range cases {
		got, reason := decide(&observation{status: tc.status, draining: tc.draining, joinedAt: joined, lastSeen: tc.lastSeen, now: joined.Add(tc.now)}, &cfg)
		if got != tc.want {
			t.Errorf("%s: got %s, want %s (%s)", tc.name, got, tc.want, reason)
		}
		if got != tc.status && reason == "" {
			t.Errorf("%s: transition without a reason", tc.name)
		}
	}
}

func TestLatestPrefersNewerHeartbeat(t *testing.T) {
	old := time.Unix(100, 0)
	if latest(nil, time.Time{}) != nil {
		t.Fatal("no data must stay nil")
	}
	if got := latest(&old, time.Unix(200, 0)); !got.Equal(time.Unix(200, 0)) {
		t.Fatal("redis is newer")
	}
	if got := latest(&old, time.Unix(50, 0)); !got.Equal(old) {
		t.Fatal("postgres is newer")
	}
}

func TestConfigValidate(t *testing.T) {
	c := cfg
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.DeadAfter = 10 * time.Second
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "must be longer than 3 heartbeat intervals") {
		t.Fatalf("dead before suspect accepted: %v", err)
	}
	c = cfg
	c.DetectorInterval = 10 * time.Second
	if err := c.Validate(); err == nil {
		t.Fatal("detector slower than heartbeats accepted")
	}
}

func TestNamesAndLabels(t *testing.T) {
	for in, want := range map[string]string{"Build-Server.local": "build-server-local", "web01": "web01", "__x__": "x"} {
		if got, err := normalizeNodeName("", in); err != nil || got != want {
			t.Errorf("hostname %q -> %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeNodeName("", "___"); err == nil {
		t.Error("underivable name accepted")
	}
	if _, err := normalizeNodeName("Bad Name", "h"); err == nil {
		t.Error("invalid requested name accepted")
	}
	labels, err := ParseLabels("zone=eu-1, gpu=true")
	if err != nil || labels["zone"] != "eu-1" || labels["gpu"] != "true" {
		t.Fatalf("labels %v %v", labels, err)
	}
	for _, bad := range []string{"novalue", "Bad=1", "k=v v", strings.Repeat("k", 70) + "=v"} {
		if _, err := ParseLabels(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "k" + strings.Repeat("a", i) + "=v"
	}
	if _, err := ParseLabels(strings.Join(many, ",")); err == nil {
		t.Error("too many labels accepted")
	}
}

func TestInfoIsSanitized(t *testing.T) {
	in := Info{Hostname: strings.Repeat("h", 400) + "\x00", CPUCount: -1, Addresses: []string{"10.0.0.1", "not-ip", "::1"}, OS: "linux"}
	out := in.sanitized()
	if len(out.Hostname) != 253 || strings.ContainsRune(out.Hostname, 0) || out.CPUCount != 0 || len(out.Addresses) != 2 {
		t.Fatalf("sanitized = %+v", out)
	}
}

func TestJoinTokenFormat(t *testing.T) {
	tok, prefix := NewJoinToken()
	if !LooksLikeJoinToken(tok) || !strings.HasPrefix(tok, prefix) || len(prefix) != len(JoinTokenPrefix)+4 {
		t.Fatalf("token %q prefix %q", tok, prefix)
	}
	for _, bad := range []string{"", "nook_join_", "nook_pat_" + tok[len(JoinTokenPrefix):], tok + "a"} {
		if LooksLikeJoinToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
