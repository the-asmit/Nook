package agent

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// The database server's bridge is filtered like apps; apps may reach only
// the current endpoint; remote clients are restricted to the listed ones.
func TestDatabaseFirewallRules(t *testing.T) {
	s := firewallSpec{
		Chain: "NOOK", AppBridge: "nka", DBBridge: "nkdb0",
		DBAllow:    []netip.Prefix{netip.MustParsePrefix("172.31.250.11/32")},
		DBClients:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		DBEndpoint: netip.MustParseAddrPort("10.0.0.7:5433"),
	}
	v4, _ := s.rules()
	for _, want := range []string{
		"-A NOOK-FWD -i nkdb0 -d 172.31.250.11/32 -j RETURN",
		"-A NOOK-FWD -i nka+ -p tcp -m conntrack --ctorigdst 10.0.0.7/32 --ctorigdstport 5433 -j RETURN",
		"-A NOOK-IN -i nka+ -p tcp -m conntrack --ctorigdst 10.0.0.7/32 --ctorigdstport 5433 -j RETURN",
		"-A NOOK-FWD -i nkdb0 -d 10.0.0.0/8 -j REJECT",
		"-A NOOK-IN -i nkdb0 -j REJECT",
		"-A NOOK-FWD -o nkdb0 -m conntrack --ctstate NEW -s 10.0.0.0/24 -j RETURN",
		"-A NOOK-FWD -o nkdb0 -m conntrack --ctstate NEW -j REJECT",
	} {
		if !strings.Contains(v4, want) {
			t.Errorf("IPv4 rules lack %q:\n%s", want, v4)
		}
	}
	allow := strings.Index(v4, "--ctorigdst 10.0.0.7/32")
	if allow < 0 || allow > strings.Index(v4, "-i nka+ -d 10.0.0.0/8 -j REJECT") {
		t.Error("the endpoint allowance must come before the app blocks")
	}
	// A new endpoint replaces the old one: a fenced server is unreachable.
	fw := &firewall{spec: s}
	if !fw.setDatabaseEndpoint(netip.MustParseAddrPort("10.0.0.8:5433")) || fw.setDatabaseEndpoint(netip.MustParseAddrPort("10.0.0.8:5433")) {
		t.Fatal("setDatabaseEndpoint must report changes only")
	}
	v4, _ = fw.spec.rules()
	if strings.Contains(v4, "10.0.0.7/32") || !strings.Contains(v4, "--ctorigdst 10.0.0.8/32 --ctorigdstport 5433") {
		t.Fatalf("the old endpoint is still allowed:\n%s", v4)
	}
	fw.setDatabaseEndpoint(netip.AddrPort{})
	if v4, _ = fw.spec.rules(); strings.Contains(v4, "ctorigdst") {
		t.Fatalf("no endpoint, yet apps may reach one:\n%s", v4)
	}
	// Without listed clients the server accepts any source (warned at startup).
	fw.spec.DBClients = nil
	if v4, _ = fw.spec.rules(); strings.Contains(v4, "-o nkdb0 -m conntrack --ctstate NEW -j REJECT") {
		t.Fatal("ingress restricted without DB clients")
	}
}

func TestDatabaseConfig(t *testing.T) {
	ok := DatabaseConfig{Port: 5433, Network: defaultDBNetwork, Addr: "10.0.0.7", ClientAddrs: []string{"10.0.0.0/24"}}
	if err := ok.validate(false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []DatabaseConfig{
		{Port: 0, Network: defaultDBNetwork},
		{Port: 5433, Network: "Bad Name"},
		{Port: 5433, Network: defaultDBNetwork, Addr: "0.0.0.0"},
		{Port: 5433, Network: defaultDBNetwork, Addr: "203.0.113.5"},
		{Port: 5433, Network: defaultDBNetwork, PublishAddr: "::"},
		{Port: 5433, Network: defaultDBNetwork, ClientAddrs: []string{"nope"}},
	} {
		if err := bad.validate(false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if err := (&DatabaseConfig{Port: 5433, Network: defaultDBNetwork, Addr: hostGateway}).validate(false); err != nil {
		t.Errorf("host-gateway: %v", err)
	}
	if dbBridge(defaultDBNetwork) != "nkdb0" || !strings.HasPrefix(dbBridge("other"), "nkd") || len(dbBridge("other")) > 15 {
		t.Errorf("bridge names %q %q", dbBridge(defaultDBNetwork), dbBridge("other"))
	}
}

func TestValidateStartDatabase(t *testing.T) {
	good := &agentv1.StartDatabaseCommand{
		ServerId: "01a21823-cfd5-76b9-bb67-9504f56a4a35", Image: "nook-postgres:dev", Mode: "restore",
		MemoryBytes: 512 << 20, CpuMillicores: 1000, Env: []*agentv1.EnvVar{{Name: "WALG_S3_PREFIX", Value: "s3://b/p"}},
	}
	if err := validateStartDatabase(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.StartDatabaseCommand){
		"id":     func(c *agentv1.StartDatabaseCommand) { c.ServerId = "../x" },
		"image":  func(c *agentv1.StartDatabaseCommand) { c.Image = "Bad Image" },
		"mode":   func(c *agentv1.StartDatabaseCommand) { c.Mode = "wipe" },
		"memory": func(c *agentv1.StartDatabaseCommand) { c.MemoryBytes = 1 },
		"env":    func(c *agentv1.StartDatabaseCommand) { c.Env = []*agentv1.EnvVar{{Name: "lower", Value: "x"}} },
		"modeEnv": func(c *agentv1.StartDatabaseCommand) {
			c.Env = []*agentv1.EnvVar{{Name: "NOOK_DB_MODE", Value: "init"}}
		},
	} {
		c := &agentv1.StartDatabaseCommand{ServerId: good.ServerId, Image: good.Image, Mode: good.Mode, MemoryBytes: good.MemoryBytes, CpuMillicores: good.CpuMillicores, Env: good.Env}
		mutate(c)
		if err := validateStartDatabase(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOutputHelpers(t *testing.T) {
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, n: 5}
	if _, err := lw.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write([]byte("def")); err == nil || !lw.exceeded || lw.written != 3 || buf.String() != "abc" {
		t.Fatalf("limit not enforced: %v %+v %q", err, lw, buf.String())
	}
	tb := &tailBuffer{max: 4}
	_, _ = tb.Write([]byte("abcdef"))
	if tb.String() != "cdef" {
		t.Fatalf("tail = %q", tb.String())
	}
	if lastLines("a\nb\nc\n", 2) != "b | c" {
		t.Fatalf("lastLines = %q", lastLines("a\nb\nc\n", 2))
	}
}
