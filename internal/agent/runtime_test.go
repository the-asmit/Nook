package agent

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

func TestFirewallRules(t *testing.T) {
	s := firewallSpec{
		Chain: "NOOK", AppBridge: "nka", BuildBridge: "nkbuild0",
		BuildAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32"), netip.MustParsePrefix("fd00::5/128")},
		Block:      []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}
	v4, v6 := s.rules()
	for _, want := range []string{
		":NOOK-FWD - [0:0]", ":NOOK-IN - [0:0]",
		"-A NOOK-FWD -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-A NOOK-FWD -i nkbuild0 -d 10.0.0.5/32 -j RETURN",
		"-A NOOK-FWD -i nka+ -p udp --dport 53 -j RETURN",
		"-A NOOK-FWD -i nka+ -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited",
		"-A NOOK-FWD -i nka+ -d 10.0.0.0/8 -j REJECT",
		"-A NOOK-FWD -i nkbuild0 -d 172.16.0.0/12 -j REJECT",
		"-A NOOK-FWD -i nka+ -d 203.0.113.0/24 -j REJECT",
		"-A NOOK-IN -i nka+ -j REJECT --reject-with icmp-admin-prohibited",
		"-A NOOK-IN -i nkbuild0 -d 10.0.0.5/32 -j RETURN",
		"COMMIT",
	} {
		if !strings.Contains(v4, want) {
			t.Errorf("IPv4 rules lack %q:\n%s", want, v4)
		}
	}
	// The allow rule for builds precedes the blocks; apps get no allowance.
	if strings.Index(v4, "-i nkbuild0 -d 10.0.0.5/32 -j RETURN") > strings.Index(v4, "-j REJECT") {
		t.Error("the build allowance comes after a REJECT")
	}
	if strings.Contains(v4, "-i nka+ -d 10.0.0.5/32 -j RETURN") || strings.Contains(v4, "fd00") || strings.Contains(v6, "10.0.0.5") {
		t.Errorf("rules mix families or allow apps:\n%s\n%s", v4, v6)
	}
	for _, want := range []string{
		"-A NOOK-FWD -i nka+ -d fc00::/7 -j REJECT --reject-with icmp6-adm-prohibited",
		"-A NOOK-FWD -i nka+ -d fe80::/10 -j REJECT",
		"-A NOOK-FWD -i nkbuild0 -d fd00::5/128 -j RETURN",
	} {
		if !strings.Contains(v6, want) {
			t.Errorf("IPv6 rules lack %q:\n%s", want, v6)
		}
	}
	// Without a managed build network only app bridges are filtered.
	s.BuildBridge = ""
	if v4, _ = s.rules(); strings.Contains(v4, "nkbuild0") {
		t.Error("build rules without a build bridge")
	}
}

func TestFirewallSpecFromConfig(t *testing.T) {
	cfg := Config{FirewallChain: "NOOK", BuildSlots: 2, BuildNetwork: managedBuildNetwork, BuildEgressAllow: []string{"10.1.2.3", "10.9.0.0/16"}}
	spec, err := firewallSpecFor(&cfg)
	if err != nil || spec.BuildBridge != managedBuildBridge || len(spec.BuildAllow) != 2 || spec.BuildAllow[0].Bits() != 32 {
		t.Fatalf("spec %+v %v", spec, err)
	}
	cfg.BuildNetwork = "shared"
	if spec, _ = firewallSpecFor(&cfg); spec.BuildBridge != "" {
		t.Fatal("a foreign build network is filtered")
	}
	cfg.EgressBlock = []string{"not-an-ip"}
	if _, err := firewallSpecFor(&cfg); err == nil {
		t.Fatal("invalid block list accepted")
	}
}

func TestProbeVerdict(t *testing.T) {
	if probeVerdict(0, "apparmor_restrict_unprivileged_userns=1") != "" {
		t.Fatal("a passing check reported a problem")
	}
	got := probeVerdict(1, "apparmor_restrict_unprivileged_userns=1\n[rootlesskit:parent] error: operation not permitted")
	if !strings.Contains(got, "kernel.apparmor_restrict_unprivileged_userns=0") || !strings.Contains(got, "sysctl") {
		t.Fatalf("AppArmor restriction: %q", got)
	}
	got = probeVerdict(1, "apparmor_restrict_unprivileged_userns=absent\nfork/exec /proc/self/exe: operation not permitted")
	if !strings.Contains(got, "fork/exec /proc/self/exe: operation not permitted") || !strings.Contains(got, "max_user_namespaces") {
		t.Fatalf("other failure: %q", got)
	}
}

func TestAppNetworkNames(t *testing.T) {
	name, bridge := appNetwork("01a21322-6d93-7115-944e-06eaa01f05c0")
	if name != "nook-app-01a21322-6d93-7115-944e-06eaa01f05c0" || bridge != "nka06eaa01f05c0" || len(bridge) > 15 {
		t.Fatalf("%q %q", name, bridge)
	}
}

func validStart() *agentv1.StartInstanceCommand {
	id := "01a21322-6d93-7115-944e-06eaa01f05c0"
	return &agentv1.StartInstanceCommand{
		InstanceId: id, DeploymentId: id, AppId: id, WorkspaceId: id,
		Registry: "registry:5000", Repository: id + "/" + id, ImageDigest: "sha256:" + strings.Repeat("a", 64), RegistryToken: "t",
		Port: 8080, HealthCheckPath: "/healthz", StartupTimeout: durationpb.New(time.Minute),
		MemoryBytes: 64 << 20, CpuMillicores: 100, Env: []*agentv1.EnvVar{{Name: "A", Value: "b"}},
	}
}

func TestValidateStart(t *testing.T) {
	if err := validateStart(validStart()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.StartInstanceCommand){
		"bad id":         func(c *agentv1.StartInstanceCommand) { c.InstanceId = "../x" },
		"bad digest":     func(c *agentv1.StartInstanceCommand) { c.ImageDigest = "latest" },
		"bad port":       func(c *agentv1.StartInstanceCommand) { c.Port = 0 },
		"bad path":       func(c *agentv1.StartInstanceCommand) { c.HealthCheckPath = "healthz" },
		"no token":       func(c *agentv1.StartInstanceCommand) { c.RegistryToken = "" },
		"tiny memory":    func(c *agentv1.StartInstanceCommand) { c.MemoryBytes = 1 },
		"env with =":     func(c *agentv1.StartInstanceCommand) { c.Env[0].Name = "A=B" },
		"env with nul":   func(c *agentv1.StartInstanceCommand) { c.Env[0].Value = "a\x00b" },
		"bad repository": func(c *agentv1.StartInstanceCommand) { c.Repository = "UPPER" },
	} {
		c := validStart()
		mutate(c)
		if validateStart(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLogBatcherSplitsLinesAndEnforcesTheLimit(t *testing.T) {
	out := newOutbox()
	b := &logBatcher{id: "s", outbox: out, limit: 30}
	w := b.writer("stderr")
	if _, err := w.Write([]byte("2026-01-02T03:04:05.000000006Z hello\n2026-01-02T03:04:06Z wor")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("ld\n")); err != nil {
		t.Fatal(err)
	}
	b.flush()
	msgs := out.take()
	if len(msgs) != 1 {
		t.Fatalf("%d messages", len(msgs))
	}
	lines := msgs[0].GetAppLog().GetLines()
	if len(lines) != 2 || lines[0].GetText() != "hello" || lines[1].GetText() != "world" || lines[0].GetStream() != "stderr" ||
		lines[0].GetTime().AsTime().Nanosecond() != 6 {
		t.Fatalf("lines %v", lines)
	}
	if _, err := w.Write([]byte("x " + strings.Repeat("y", 40) + "\n")); err == nil {
		t.Fatal("the byte limit was not enforced")
	}
}

func TestProxyConfig(t *testing.T) {
	if (proxyConfig{}).env("registry") != nil || (proxyConfig{}).buildArgs() != nil {
		t.Fatal("no proxy must add nothing")
	}
	p := proxyConfig{HTTP: "proxy:3128", HTTPS: "http://proxy:3128", NoProxy: "internal"}
	env := strings.Join(p.env("registry"), " ")
	if !strings.Contains(env, "HTTP_PROXY=http://proxy:3128") || !strings.Contains(env, "NO_PROXY=localhost,127.0.0.1,registry,internal") {
		t.Fatalf("env %s", env)
	}
	if args := strings.Join(p.buildArgs(), " "); !strings.Contains(args, "--opt build-arg:HTTPS_PROXY=http://proxy:3128") {
		t.Fatalf("build args %s", args)
	}
	if registryHost("registry:5000") != "registry" || registryHost("registry") != "registry" {
		t.Fatal("registryHost")
	}
}
