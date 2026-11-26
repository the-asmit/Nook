package routes

import (
	"strings"
	"testing"
)

func TestParseBase(t *testing.T) {
	b, err := ParseBase("https://apps.example.com")
	if err != nil || b.Scheme != "https" || b.Domain != "apps.example.com" || b.Port != "" {
		t.Fatalf("%+v %v", b, err)
	}
	b, err = ParseBase("http://Apps.LocalHost:8081/")
	if err != nil || b.Domain != "apps.localhost" || b.Port != "8081" {
		t.Fatalf("%+v %v", b, err)
	}
	for _, bad := range []string{"", "apps.example.com", "ftp://apps.example.com", "https://localhost", "https://10.0.0.1", "https://apps.example.com/x", "https://u@apps.example.com"} {
		if _, err := ParseBase(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHostNames(t *testing.T) {
	b := Base{Scheme: "https", Domain: "apps.example.com"}
	if got := b.Host("acme", "web"); got != "web--acme.apps.example.com" {
		t.Fatal(got)
	}
	if got := b.URL("acme", "web"); got != "https://web--acme.apps.example.com/" {
		t.Fatal(got)
	}
	if got := (Base{Scheme: "http", Domain: "apps.localhost", Port: "8081"}).URL("alice", "hello-go"); got != "http://hello-go--alice.apps.localhost:8081/" {
		t.Fatal(got)
	}
	if b.AuthHost() != "auth.apps.example.com" {
		t.Fatal(b.AuthHost())
	}
	for host, want := range map[string][2]string{
		"web--acme.apps.example.com":     {"acme", "web"},
		"WEB--ACME.apps.example.com.":    {"acme", "web"},
		"my-app--my-ws.apps.example.com": {"my-ws", "my-app"},
	} {
		ws, app, ok := b.Parse(host)
		if !ok || ws != want[0] || app != want[1] {
			t.Errorf("Parse(%q) = %q %q %v", host, ws, app, ok)
		}
	}
	for _, host := range []string{
		"auth.apps.example.com", "apps.example.com", "web.apps.example.com", "x.web--acme.apps.example.com",
		"web--acme.apps.example.com.evil.com", "web--acme.other.com", "--acme.apps.example.com", "web--.apps.example.com",
		"a--b--c.apps.example.com",
	} {
		if _, _, ok := b.Parse(host); ok {
			t.Errorf("Parse(%q) accepted", host)
		}
	}
}

func TestValidLabel(t *testing.T) {
	if !ValidLabel("acme", "web") || ValidLabel("acme", "a--b") || ValidLabel("a--b", "web") {
		t.Fatal("double hyphen rules")
	}
	if ValidLabel(strings.Repeat("w", 40), strings.Repeat("a", 22)) {
		t.Fatal("64-character label accepted")
	}
	if !ValidLabel(strings.Repeat("w", 40), strings.Repeat("a", 21)) {
		t.Fatal("63-character label rejected")
	}
}

func TestStates(t *testing.T) {
	for _, c := range []struct {
		desired  string
		deployed bool
		instance string
		want     string
	}{
		{"running", true, "healthy", StateRunning},
		{"running", true, "unhealthy", StateUnhealthy},
		{"running", true, "starting", StateStarting},
		{"running", true, "", StateStarting},
		{"running", true, "crashed", StateCrashed},
		{"running", false, "", StateNotDeployed},
		{"stopped", true, "healthy", StateStopped},
		{"running", true, "stopped", StateStopped},
	} {
		if got := StateOf(c.desired, c.deployed, c.instance); got != c.want {
			t.Errorf("StateOf(%s, %v, %s) = %s, want %s", c.desired, c.deployed, c.instance, got, c.want)
		}
	}
	r := Route{State: StateRunning, Upstream: "10.0.0.5:30001"}
	if !r.Serving() || (&Route{State: StateStopped, Upstream: "x"}).Serving() || (&Route{State: StateRunning}).Serving() {
		t.Fatal("Serving")
	}
	if Effective(AccessPublic, false) != AccessWorkspace || Effective(AccessPublic, true) != AccessPublic || Effective(AccessRestricted, false) != AccessRestricted {
		t.Fatal("Effective")
	}
}
