//go:build integration

package server

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/testinfra"
)

// TestCrashesAreRestartedAndCrashLoopsDetected: a killed app process is
// restarted after a backoff; crashing more often than the limit within
// the window makes the instance crashed (no more restarts), which the app
// shows until it is started again.
func TestCrashesAreRestartedAndCrashLoopsDetected(t *testing.T) {
	r := startRuntimeEnvWith(t, nil, map[string]string{
		"NOOK_AGENT_CRASH_LIMIT": "2", "NOOK_AGENT_CRASH_WINDOW": "1m",
		"NOOK_AGENT_RESTART_BACKOFF_MIN": "200ms", "NOOK_AGENT_RESTART_BACKOFF_MAX": "1s",
	})
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	n := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n)

	crash := func(wantRestarts int32) {
		t.Helper()
		_, _ = get(r.appBase(r.alice, r.ws, "web") + "/crash")
		eventually(t, time.Minute, "the instance to come back", func() bool {
			a := r.app(r.alice, r.ws, "web")
			return a.Instance != nil && a.Instance.State == "healthy" && a.Instance.RestartCount == wantRestarts
		})
		if code, _ := get(r.appBase(r.alice, r.ws, "web") + "/healthz"); code != http.StatusOK {
			t.Fatalf("the restarted app does not answer: %d", code)
		}
	}
	crash(1)
	crash(2)
	_, _ = get(r.appBase(r.alice, r.ws, "web") + "/crash")
	var a appState
	eventually(t, time.Minute, "the crash loop to be detected", func() bool {
		a = r.app(r.alice, r.ws, "web")
		return a.Health == "crashed"
	})
	if a.Instance.State != "crashed" || a.Instance.RestartCount != 3 ||
		!strings.Contains(a.Instance.LastError, "exited with code 3") || !strings.Contains(a.Instance.LastError, "crashed 3 times within 1m0s") {
		t.Fatalf("crashed instance %+v", a.Instance)
	}
	// No restart happens any more.
	eventuallyStays(t, 3*time.Second, "the crashed instance to stay down", func() bool {
		return r.app(r.alice, r.ws, "web").Instance.State == "crashed"
	})

	expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/start", nil), http.StatusOK, "start")
	eventually(t, time.Minute, "a fresh instance", func() bool {
		a = r.app(r.alice, r.ws, "web")
		return a.Health == "running" && a.Instance.RestartCount == 0
	})
	if code, _ := get(r.appBase(r.alice, r.ws, "web") + "/healthz"); code != http.StatusOK {
		t.Fatalf("the restarted app does not answer: %d", code)
	}
}

// eventuallyStays checks that cond holds at every poll until the period
// passes.
func eventuallyStays(t *testing.T, period time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(period)
	for time.Now().Before(deadline) {
		if !cond() {
			t.Fatalf("%s: the condition stopped holding", what)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		<-timer.C
	}
}

// TestAppContainersAreLockedDown inspects a running app container: every
// capability dropped, no privilege escalation, limits, no host mounts or
// Docker socket, its own network, the port published on the advertise
// address only, rotated logs and no Docker restart policy.
func TestAppContainersAreLockedDown(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", map[string]any{"memory_mb": 96, "cpu_millicores": 250, "read_only_rootfs": true})
	n := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n)
	_, appID := r.appIDs(r.ws, "web")
	d := dockerClient(t)
	list, err := d.ContainerList(context.Background(), client.ContainerListOptions{Filters: client.Filters{}.Add("label", "nook.app="+appID.String())})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("app containers: %v %d", err, len(list.Items))
	}
	res, err := d.ContainerInspect(context.Background(), list.Items[0].ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c, hc := res.Container, res.Container.HostConfig
	checks := map[string]bool{
		"cap drop ALL":         len(hc.CapDrop) == 1 && hc.CapDrop[0] == "ALL" && len(hc.CapAdd) == 0,
		"no new privileges":    len(hc.SecurityOpt) == 1 && hc.SecurityOpt[0] == "no-new-privileges:true",
		"not privileged":       !hc.Privileged,
		"memory limit":         hc.Memory == 96<<20 && hc.MemorySwap == 96<<20,
		"cpu limit":            hc.NanoCPUs == 250_000_000,
		"pids limit":           hc.PidsLimit != nil && *hc.PidsLimit == 1024,
		"read-only rootfs":     hc.ReadonlyRootfs,
		"tmpfs /tmp only":      len(hc.Tmpfs) == 1 && strings.Contains(hc.Tmpfs["/tmp"], "noexec"),
		"no binds":             len(hc.Binds) == 0 && len(hc.Mounts) == 0,
		"no host namespaces":   hc.PidMode == "" && hc.IpcMode != "host" && hc.UsernsMode == "",
		"own network":          string(hc.NetworkMode) == "nook-app-"+appID.String(),
		"no restart policy":    hc.RestartPolicy.Name == container.RestartPolicyDisabled,
		"rotated logs":         hc.LogConfig.Type == "json-file" && hc.LogConfig.Config["max-size"] == "10m" && hc.LogConfig.Config["max-file"] == "3",
		"default seccomp":      !strings.Contains(strings.Join(hc.SecurityOpt, ","), "seccomp"),
		"labels":               c.Config.Labels["nook.workspace"] != "" && c.Config.Labels["nook.deployment"] != "",
		"image's own user":     c.Config.User == "65532:65532",
		"no docker socket env": !strings.Contains(strings.Join(c.Config.Env, ","), "DOCKER_HOST"),
	}
	for _, m := range c.Mounts {
		if m.Type != "tmpfs" || strings.Contains(m.Source, "docker.sock") {
			checks["only the tmpfs mount"] = false
		}
	}
	port, _ := network.ParsePort("8080/tcp")
	bindings := hc.PortBindings[port]
	checks["port on the advertise address only"] = len(bindings) == 1 && bindings[0].HostIP == netip.MustParseAddr("127.0.0.1")
	for name, ok := range checks {
		if !ok {
			t.Errorf("%s: not as required (%+v)", name, hc)
		}
	}
	base := r.appBase(r.alice, r.ws, "web")
	if _, body := get(base + "/write?path=/data.txt"); body != "false" {
		t.Errorf("the read-only root file system is writable: %q", body)
	}
	if _, body := get(base + "/write?path=/tmp/data.txt"); body != "true" {
		t.Errorf("/tmp is not writable: %q", body)
	}
	// The network keeps containers apart.
	nw, err := d.NetworkInspect(context.Background(), "nook-app-"+appID.String(), client.NetworkInspectOptions{})
	if err != nil || nw.Network.Options["com.docker.network.bridge.enable_icc"] != "false" ||
		!strings.HasPrefix(nw.Network.Options["com.docker.network.bridge.name"], "nka") {
		t.Errorf("app network %+v: %v", nw.Network.Options, err)
	}
}

// Stand-ins for the egress tests. Real cloud metadata and the internet are
// not available (or not wanted) in tests, so local servers take their
// place in networks whose containers Docker lets other networks reach
// (gateway mode nat-unprotected): without Nook's firewall, an app could
// reach both.
const (
	metadataStandIn = "169.254.169.254"
	publicStandIn   = "198.51.100.10" // TEST-NET-2: not a private range
	standInImage    = "busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)

// startStandIn runs an HTTP server at ip in a reachable network.
func startStandIn(t *testing.T, name, subnet, ip string) {
	t.Helper()
	ctx := context.Background()
	d := dockerClient(t)
	prefix := netip.MustParsePrefix(subnet)
	_, _ = d.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
	_, _ = d.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	if _, err := d.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver:  "bridge",
		IPAM:    &network.IPAM{Config: []network.IPAMConfig{{Subnet: prefix}}},
		Options: map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "nat-unprotected"},
	}); err != nil {
		t.Fatal(err)
	}
	// A native engine drops traffic between bridge networks; the stand-in
	// is another host on a routed network (an agent's firewall, inserted
	// above these rules, still filters it).
	unroute, err := testinfra.AllowRouting(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unroute)
	// Pinned by digest: a local copy is the same image.
	if _, inspectErr := d.ImageInspect(ctx, standInImage); inspectErr != nil {
		pull, pullErr := d.ImagePull(ctx, standInImage, client.ImagePullOptions{})
		if pullErr != nil {
			t.Fatal(pullErr)
		}
		if err = pull.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	created, err := d.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:       name,
		Config:     &container.Config{Image: standInImage, Cmd: []string{"sh", "-c", "mkdir /w && echo " + name + " > /w/index.html && httpd -f -p 80 -h /w"}},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(name)},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			name: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr(ip)}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = d.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true})
		_, _ = d.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	})
}

// fetchFrom runs wget in a throwaway container on network nw.
func fetchFrom(t *testing.T, nw, target string) bool {
	t.Helper()
	return runProbe(t, nw, []string{"wget", "-q", "-T", "3", "-O", "-", target})
}

// runProbe runs cmd in a throwaway busybox container on network nw and
// reports whether it succeeded.
func runProbe(t *testing.T, nw string, cmd []string) bool {
	t.Helper()
	ctx := context.Background()
	d := dockerClient(t)
	created, err := d.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     &container.Config{Image: standInImage, Cmd: cmd},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(nw)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{Force: true}) }()
	wait := d.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	if _, err := d.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-wait.Result:
		return res.StatusCode == 0
	case err := <-wait.Error:
		t.Fatal(err)
	}
	return false
}

// TestAppEgressIsFiltered: from an app container the metadata stand-in,
// another app's container and the node itself are unreachable, while the
// public stand-in answers, and DNS lookups work. A plain container on an
// ordinary network reaches both stand-ins, which shows the block is
// Nook's firewall.
func TestAppEgressIsFiltered(t *testing.T) {
	startStandIn(t, "nook-test-metadata", "169.254.169.0/24", metadataStandIn)
	startStandIn(t, "nook-test-public", "198.51.100.0/24", publicStandIn)
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.newRuntimeApp(r.alice, r.ws, "other", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	r.waitLive(r.alice, r.ws, "other", r.release(r.ws, "other"))

	if !fetchFrom(t, "bridge", "http://"+metadataStandIn+"/") || !fetchFrom(t, "bridge", "http://"+publicStandIn+"/") {
		t.Fatal("the stand-ins are not reachable from an ordinary container; the test proves nothing")
	}
	base := r.appBase(r.alice, r.ws, "web")
	fetch := func(url string) string {
		_, body := get(base + "/fetch?url=" + url)
		return body
	}
	if code, _ := get(r.appBase(r.alice, r.ws, "other") + "/healthz"); code != http.StatusOK {
		t.Fatalf("the other app does not run: %d", code)
	}
	if got := fetch("http://" + publicStandIn + "/"); got != "status 200" {
		t.Fatalf("public stand-in from the app: %q", got)
	}
	if got := fetch("http://" + metadataStandIn + "/"); !strings.HasPrefix(got, "error") {
		t.Fatalf("metadata stand-in reachable from the app: %q", got)
	}
	// DNS works from the app (through the resolvers the agent allows).
	if dnsName := offlineDNSName(t); dnsName != "" {
		appResolves(t, base, dnsName)
	}
	_, otherID := r.appIDs(r.ws, "other")
	d := dockerClient(t)
	list, err := d.ContainerList(context.Background(), client.ContainerListOptions{Filters: client.Filters{}.Add("label", "nook.app="+otherID.String())})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("other app containers: %v", err)
	}
	info, err := d.ContainerInspect(context.Background(), list.Items[0].ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range info.Container.NetworkSettings.Networks {
		if got := fetch("http://" + ep.IPAddress.String() + ":8080/healthz"); !strings.HasPrefix(got, "error") {
			t.Fatalf("another app's container is reachable: %q", got)
		}
		if got := fetch("http://" + ep.Gateway.String() + ":8080/"); !strings.HasPrefix(got, "error") {
			t.Fatalf("the node is reachable through the gateway: %q", got)
		}
	}
}

// TestBuildEgressIsFiltered runs a real build (its base image comes from
// the registry, so it needs no internet) whose RUN steps probe the
// network: the registry, which builds push to, is reachable; the metadata
// stand-in and the node itself (the build network's gateway, on a port the
// node publishes) are not; the public stand-in is, and DNS lookups work.
// An ordinary container
// reaches the metadata stand-in and the node port, which shows the
// blocks are the agent's firewall.
func TestBuildEgressIsFiltered(t *testing.T) {
	startStandIn(t, "nook-test-metadata", "169.254.169.0/24", metadataStandIn)
	startStandIn(t, "nook-test-public", "198.51.100.0/24", publicStandIn)
	b := startBuildEnv(t, nil)
	nodePort := postgresPort(t)
	if !fetchFrom(t, "bridge", "http://"+metadataStandIn+"/") || !tcpFrom(t, "bridge", networkGateway(t, "bridge"), nodePort) {
		t.Fatal("the stand-ins are not reachable from an ordinary container; the test proves nothing")
	}
	gateway := networkGateway(t, shared.buildNetwork)
	dnsName := offlineDNSName(t)
	b.createApp(b.alice, b.ws, "probe")
	probe := func(name, host, port string) string {
		return "RUN (nc -z -w 3 " + host + " " + port + " && echo " + name + "-REACHABLE) || echo " + name + "-BLOCKED\n"
	}
	n := b.deploy(b.alice, b.ws, "probe", project(t, map[string]string{
		"Dockerfile": "FROM __BASE__\n" +
			probe("REGISTRY", testinfra.RegistryAlias, "5000") +
			probe("METADATA", metadataStandIn, "80") +
			probe("NODE", gateway, nodePort) +
			probe("PUBLIC", publicStandIn, "80") +
			dnsProbe(dnsName),
	}))
	d := b.waitStatus(b.alice, b.ws, "probe", n, 3*time.Minute, "built", "failed")
	log := b.buildLog(b.alice, b.ws, "probe", n)
	// Output lines look like "#7 0.512 METADATA-BLOCKED"; the echoed RUN
	// commands contain the markers too, so only output lines count.
	output := func(marker string) bool {
		return regexp.MustCompile(`(?m)^#\d+ \d+\.\d+ ` + marker + `$`).MatchString(log)
	}
	wants := []string{"REGISTRY-REACHABLE", "METADATA-BLOCKED", "NODE-BLOCKED", "PUBLIC-REACHABLE"}
	if dnsName != "" {
		wants = append(wants, "DNS-RESOLVED")
	}
	for _, want := range wants {
		if !output(want) {
			t.Errorf("no %s in the build output", want)
		}
	}
	if d.Status != "built" || t.Failed() {
		t.Fatalf("deployment %s; build log:\n%s", d.Status, log)
	}
}

// firstResolvable returns the first candidate that a plain container on
// an ordinary user-defined network (Docker's embedded resolver, like app
// and build networks, without Nook's firewall) resolves within 30 s, or ""
// if none does.
func firstResolvable(t *testing.T, candidates ...string) string {
	t.Helper()
	ctx := context.Background()
	d := dockerClient(t)
	name := "nook-test-plain-dns"
	_, _ = d.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	if _, err := d.NetworkCreate(ctx, name, client.NetworkCreateOptions{Driver: "bridge"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.NetworkRemove(context.Background(), name, client.NetworkRemoveOptions{}) })
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, candidate := range candidates {
			if runProbe(t, name, []string{"nslookup", candidate}) {
				return candidate
			}
		}
	}
	return ""
}

// offlineDNSName is a name the node's resolver answers without the
// internet: host.docker.internal on Docker Desktop. Elsewhere it is "" and
// the tests below leave the lookup through the node's resolver to
// TestDNSReachesOnlyTheResolvers (a stand-in resolver) and to the internet
// suite (public names), so this suite stays deterministic.
func offlineDNSName(t *testing.T) string {
	t.Helper()
	name := firstResolvable(t, "host.docker.internal")
	if name == "" {
		t.Log("no name resolves here without the internet; DNS through the node's resolver is covered by the internet suite")
	}
	return name
}

// appResolves waits until the test app at base resolves name.
func appResolves(t *testing.T, base, name string) {
	t.Helper()
	eventually(t, 30*time.Second, "the app to resolve "+name, func() bool {
		_, body := get(base + "/resolve?name=" + name)
		return strings.HasPrefix(body, "ok ")
	})
}

// dnsProbe is a RUN step that prints DNS-RESOLVED if name resolves ("":
// no step).
func dnsProbe(name string) string {
	if name == "" {
		return ""
	}
	return "RUN (nslookup " + name + " >/dev/null && echo DNS-RESOLVED) || echo DNS-FAILED\n"
}

// postgresPort is a port the node publishes (the shared Postgres).
func postgresPort(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(shared.pgAdminURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

// networkGateway is a Docker network's gateway address (the node).
func networkGateway(t *testing.T, name string) string {
	t.Helper()
	res, err := dockerClient(t).NetworkInspect(context.Background(), name, client.NetworkInspectOptions{})
	if err != nil || len(res.Network.IPAM.Config) == 0 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return res.Network.IPAM.Config[0].Gateway.String()
}

// tcpFrom reports whether a container on network nw connects to host:port.
func tcpFrom(t *testing.T, nw, host, port string) bool {
	t.Helper()
	return runProbe(t, nw, []string{"nc", "-z", "-w", "3", host, port})
}

// TestRestartCountSurvivesAgentRestarts: an instance's restart count is
// restored when a restarted agent adopts its container.
func TestRestartCountSurvivesAgentRestarts(t *testing.T) {
	// A restart, not a death: with the tests' 4 s threshold a slow restart
	// on a busy machine would fail the instance over (a new instance
	// counts from zero).
	r := startRuntimeEnvWith(t, map[string]string{"NOOK_NODE_DEAD_AFTER": "2m"},
		map[string]string{"NOOK_AGENT_RESTART_BACKOFF_MIN": "200ms", "NOOK_AGENT_RESTART_BACKOFF_MAX": "1s"})
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	crashAndWait := func(want int32) {
		t.Helper()
		_, _ = get(r.appBase(r.alice, r.ws, "web") + "/crash")
		eventually(t, time.Minute, "restart "+itoa(want), func() bool {
			a := r.app(r.alice, r.ws, "web")
			return a.Instance != nil && a.Instance.State == "healthy" && a.Instance.RestartCount == want
		})
	}
	crashAndWait(1)
	r.agent.stop()
	if ok, _ := r.agent.exited(15 * time.Second); !ok {
		t.Fatal("agent did not stop")
	}
	cfg := agentConfigWith(t, r.agentState, map[string]string{"NOOK_AGENT_RESTART_BACKOFF_MIN": "200ms", "NOOK_AGENT_RESTART_BACKOFF_MAX": "1s"})
	r.agent = runConfiguredAgent(t, &cfg, quietLogger)
	eventually(t, 30*time.Second, "the agent to reconnect", func() bool { return r.agent.Connected() })
	crashAndWait(2)
}
