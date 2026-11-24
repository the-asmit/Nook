//go:build integration

package server

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/leader"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/testinfra"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// secondInstance starts another control plane on the env's database with
// its own HTTP and gRPC ports.
func (e *env) secondInstance() *instance {
	e.t.Helper()
	return e.startInstance(map[string]string{"NOOK_HTTP_ADDR": "127.0.0.1:0"})
}

// lockHolder returns the backend PID holding the failure-detector lock, or 0.
func (e *env) lockHolder() int {
	e.t.Helper()
	var pid int
	err := e.db.QueryRow(context.Background(), `SELECT coalesce(max(pid), 0) FROM pg_locks
		WHERE locktype = 'advisory' AND granted
		AND ((classid::bigint << 32) | objid::bigint) = $1`, leader.FailureDetectorLockID).Scan(&pid)
	if err != nil {
		e.t.Fatal(err)
	}
	return pid
}

// history returns a node's transitions as "from->to" strings.
func (e *env) history(name string) []string {
	e.t.Helper()
	rows, err := e.db.Query(context.Background(), `SELECT coalesce(ev.from_status::text, ''), ev.to_status::text
		FROM node_events ev JOIN nodes n ON n.id = ev.node_id WHERE n.name = $1 ORDER BY ev.id`, name)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, from+"->"+to)
	}
	return out
}

// TestLeaderFailover covers the multi-instance design: the agent is
// connected to a non-leader, the leader still sees its heartbeats and can
// command it, and when the leader's lock connection dies or the leader
// stops, the other instance takes over within a bounded time and keeps
// detecting failures.
func TestLeaderFailover(t *testing.T) {
	e := startEnv(t)
	a := e.primary
	eventually(t, 5*time.Second, "instance A to lead", a.srv.IsLeader)
	b := e.secondInstance()
	if b.srv.IsLeader() {
		t.Fatal("two leaders")
	}

	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	ag := runAgent(t, joinAgent(t, b.grpc, token, caHash, "on-b"))
	eventually(t, 15*time.Second, "agent connected to B", ag.Connected)
	// Only the leader (A) runs the failure detector, so "ready" proves A
	// sees heartbeats that arrived at B.
	eventually(t, 10*time.Second, "A marks the node ready", func() bool { return e.nodeStatus(alice, "on-b") == "ready" })
	if b.srv.IsLeader() {
		t.Fatal("B became leader while A held the lock")
	}
	// A command sent through A reaches the agent connected to B.
	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/nodes/on-b/inspect", nil), 200, "inspect through A")

	// Killing the lock connection ends A's leadership; someone holds the
	// lock again within the bound.
	before := e.lockHolder()
	if before == 0 {
		t.Fatal("nobody holds the leader lock")
	}
	e.exec("SELECT pg_terminate_backend($1)", before)
	eventually(t, 5*time.Second, "a new lock session", func() bool {
		pid := e.lockHolder()
		return pid != 0 && pid != before && (a.srv.IsLeader() != b.srv.IsLeader())
	})

	// Stop the current leader entirely: the survivor leads within the
	// bound and keeps detecting failures.
	current, survivor := a, b
	if b.srv.IsLeader() {
		current, survivor = b, a
	}
	current.stop()
	e.base = survivor.base
	start := time.Now()
	eventually(t, 5*time.Second, "the survivor to lead", survivor.srv.IsLeader)
	t.Logf("survivor took over %s after the leader stopped", time.Since(start).Round(time.Millisecond))

	ag.stop()
	eventually(t, 10*time.Second, "the node becomes suspect", func() bool { return e.nodeStatus(alice, "on-b") == "suspect" })
	eventually(t, 10*time.Second, "the node becomes dead", func() bool { return e.nodeStatus(alice, "on-b") == "dead" })
	want := []string{"->joining", "joining->ready", "ready->suspect", "suspect->dead"}
	if got := e.history("on-b"); !slices.Equal(got, want) {
		t.Fatalf("node_events = %v, want %v", got, want)
	}
}

func TestAgentReconnectsAfterRestart(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	addr := e.primary.grpc
	ag := runAgent(t, joinAgent(t, addr, token, caHash, "phoenix"))
	eventually(t, 15*time.Second, "agent connected", ag.Connected)

	e.primary.stop()
	eventually(t, 10*time.Second, "agent notices the restart", func() bool { return !ag.Connected() })

	restarted := e.startInstance(map[string]string{"NOOK_GRPC_ADDR": addr})
	e.primary, e.base, e.logs = restarted, restarted.base, restarted.logs
	eventually(t, 15*time.Second, "agent reconnects", ag.Connected)
	eventually(t, 10*time.Second, "node ready again", func() bool { return e.nodeStatus(alice, "phoenix") == "ready" })
}

// inspectAsync starts POST /nodes/{name}/inspect and delivers the response.
func (e *env) inspectAsync(u user, name string) <-chan response {
	out := make(chan response, 1)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.base+"/api/v1/nodes/"+name+"/inspect", http.NoBody)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+u.token)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			out <- response{body: err.Error()}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		out <- response{status: resp.StatusCode, body: string(b)}
	}()
	return out
}

func waitResponse(t *testing.T, ch <-chan response) response {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("request did not finish")
		return response{}
	}
}

// recvCommand reads the next command from a hand-written agent's stream,
// failing the test instead of hanging if none arrives.
func recvCommand(t *testing.T, stream agentv1.NodeService_ConnectClient) *agentv1.Command {
	t.Helper()
	type recv struct {
		m   *agentv1.ConnectResponse
		err error
	}
	ch := make(chan recv, 1)
	go func() {
		m, err := stream.Recv()
		ch <- recv{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil || r.m.GetCommand() == nil {
			t.Fatalf("expected a command, got %v %v", r.m, r.err)
		}
		return r.m.GetCommand()
	case <-time.After(10 * time.Second):
		t.Fatal("no command arrived")
		return nil
	}
}

// fakeAgent is a hand-written agent session. Like the real agent it
// heartbeats in the background (only an agent that heartbeats counts as
// connected); Send is serialized because gRPC streams allow one sender.
type fakeAgent struct {
	stream agentv1.NodeService_ConnectClient
	mu     sync.Mutex
}

func newFakeAgent(ctx context.Context, stream agentv1.NodeService_ConnectClient) *fakeAgent {
	f := &fakeAgent{stream: stream}
	hb := &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
		MemoryAvailableBytes: 1 << 30, AgentVersion: "test",
	}}}
	_ = f.send(hb)
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if f.send(hb) != nil {
					return
				}
			}
		}
	}()
	return f
}

func (f *fakeAgent) send(m *agentv1.ConnectRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stream.Send(m)
}

// TestCommandFailures drives a hand-written agent to show every way a
// command can end without an answer.
func TestCommandFailures(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	cert := agentIdentity(t, joinAgent(t, e.primary.grpc, token, caHash, "flaky"))
	client := rawClient(t, e.primary.grpc, &cert)

	r := e.as(alice, http.MethodPost, "/api/v1/nodes/flaky/inspect", nil)
	if r.status != http.StatusServiceUnavailable || r.errorCode(t) != "node_not_connected" {
		t.Fatalf("not connected: %d %s", r.status, r.body)
	}

	// The agent receives the command, then its connection drops.
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := openSessionCtx(ctx, t, client)
	if err != nil {
		t.Fatal(err)
	}
	newFakeAgent(ctx, stream)
	pending := e.inspectAsync(alice, "flaky")
	if cmd := recvCommand(t, stream); cmd.GetInspectNode() == nil {
		t.Fatalf("unexpected command %v", cmd)
	}
	cancel()
	r = waitResponse(t, pending)
	if r.status != http.StatusServiceUnavailable || r.errorCode(t) != "agent_disconnected" {
		t.Fatalf("disconnect mid-command: %d %s", r.status, r.body)
	}

	// The agent stays connected but never answers.
	var silent agentv1.NodeService_ConnectClient
	eventually(t, 5*time.Second, "a new session", func() bool {
		silent, err = openSession(t, client)
		return err == nil
	})
	silentAgent := newFakeAgent(context.Background(), silent)
	start := time.Now()
	pending = e.inspectAsync(alice, "flaky")
	cmd := recvCommand(t, silent)
	if got := cmd.GetTimeout().AsDuration(); got != 2*time.Second {
		t.Fatalf("command carries timeout %s", got)
	}
	r = waitResponse(t, pending)
	if r.status != http.StatusGatewayTimeout || r.errorCode(t) != "command_timeout" {
		t.Fatalf("unanswered command: %d %s", r.status, r.body)
	}
	if took := time.Since(start); took < 2*time.Second || took > 5*time.Second {
		t.Fatalf("timeout took %s", took)
	}

	// A late answer is ignored; the next command gets exactly its own result.
	late := &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_CommandResult{CommandResult: &agentv1.CommandResult{
		CommandId: cmd.GetCommandId(), Result: &agentv1.CommandResult_InspectNode{InspectNode: &agentv1.InspectNodeResult{}},
	}}}
	if err := silentAgent.send(late); err != nil {
		t.Fatal(err)
	}
	pending = e.inspectAsync(alice, "flaky")
	next := recvCommand(t, silent)
	answer := &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_CommandResult{CommandResult: &agentv1.CommandResult{
		CommandId: next.GetCommandId(),
		Result: &agentv1.CommandResult_InspectNode{InspectNode: &agentv1.InspectNodeResult{
			Docker: &agentv1.DockerInfo{ServerVersion: "fake-1.0"},
		}},
	}}}
	for range 2 {
		if err := silentAgent.send(answer); err != nil {
			t.Fatal(err)
		}
	}
	r = waitResponse(t, pending)
	if r.status != http.StatusOK || !strings.Contains(r.body, "fake-1.0") {
		t.Fatalf("answered command: %d %s", r.status, r.body)
	}
}

func TestDrainAndUndrain(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	runAgent(t, joinAgent(t, e.primary.grpc, token, caHash, "busy"))
	eventually(t, 15*time.Second, "node ready", func() bool { return e.nodeStatus(alice, "busy") == "ready" })

	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/nodes/busy/drain", nil), 200, "drain")
	if s := e.nodeStatus(alice, "busy"); s != "draining" {
		t.Fatalf("after drain: %s", s)
	}
	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/nodes/busy/undrain", nil), 200, "undrain")
	if s := e.nodeStatus(alice, "busy"); s != "ready" {
		t.Fatalf("after undrain: %s", s)
	}
	actions := e.auditActions()
	for _, want := range []string{"node.drain", "node.undrain"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

// TestAdminRoutesRequireInstanceAdmin checks every admin route refuses a
// signed-in non-admin.
func TestAdminRoutesRequireInstanceAdmin(t *testing.T) {
	e := startEnv(t)
	bob := e.newUser("bob@nook.test")
	for _, rt := range [][2]string{
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPatch, "/api/v1/admin/users/" + bob.id.String()},
		{http.MethodGet, "/api/v1/nodes"},
		{http.MethodGet, "/api/v1/nodes/x"},
		{http.MethodPost, "/api/v1/nodes/x/inspect"},
		{http.MethodPost, "/api/v1/nodes/x/drain"},
		{http.MethodPost, "/api/v1/nodes/x/undrain"},
		{http.MethodDelete, "/api/v1/nodes/x"},
		{http.MethodGet, "/api/v1/join-tokens"},
		{http.MethodPost, "/api/v1/join-tokens"},
		{http.MethodDelete, "/api/v1/join-tokens/00000000-0000-0000-0000-000000000000"},
	} {
		var body any
		if rt[0] == http.MethodPost || rt[0] == http.MethodPatch {
			body = map[string]any{}
		}
		expectStatus(t, e.as(bob, rt[0], rt[1], body), http.StatusForbidden, rt[0]+" "+rt[1])
		expectStatus(t, e.bearer("", rt[0], rt[1], body), http.StatusUnauthorized, "anonymous "+rt[0]+" "+rt[1])
	}
}

// TestDisablingUserRevokesAccessAtOnce uses a real browser session for the
// administrator, so the CSRF protection of the admin routes is exercised.
func TestDisablingUserRevokesAccessAtOnce(t *testing.T) {
	e := startEnv(t)
	admin := e.browser()
	admin.signIn(testinfra.DexAlice)
	bob := e.newUser("bob@nook.test")

	st := store.NewStore(e.db)
	raw, _, err := auth.NewSessions(st, auth.Config{SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 2 * time.Hour}).
		Create(context.Background(), st.Queries, bob.id, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	bobBrowser := e.browser()
	bobBrowser.setSessionCookie(raw)
	expectStatus(t, e.as(bob, http.MethodGet, "/api/v1/me", nil), 200, "bob's token before")
	expectStatus(t, bobBrowser.api(http.MethodGet, "/api/v1/me", nil, nil), 200, "bob's session before")

	patch := func(target string, body any, csrf bool) response {
		headers := map[string]string{"Origin": e.base}
		if csrf {
			headers["X-CSRF-Token"] = admin.csrf()
		}
		return admin.api(http.MethodPatch, "/api/v1/admin/users/"+target, body, headers)
	}
	expectStatus(t, patch(bob.id.String(), map[string]bool{"disabled": true}, false), 403, "disable without CSRF token")
	expectStatus(t, e.as(bob, http.MethodGet, "/api/v1/me", nil), 200, "bob unaffected by the rejected request")

	expectStatus(t, patch(bob.id.String(), map[string]bool{"disabled": true}, true), 200, "disable bob")
	expectStatus(t, e.as(bob, http.MethodGet, "/api/v1/me", nil), 401, "bob's token after")
	expectStatus(t, bobBrowser.api(http.MethodGet, "/api/v1/me", nil, nil), 401, "bob's session after")

	var aliceID string
	if err := e.db.QueryRow(context.Background(), "SELECT id::text FROM users WHERE email = $1", testinfra.DexAlice).Scan(&aliceID); err != nil {
		t.Fatal(err)
	}
	r := patch(aliceID, map[string]bool{"disabled": true}, true)
	if r.status != http.StatusConflict || r.errorCode(t) != "cannot_disable_self" {
		t.Fatalf("self-disable: %d %s", r.status, r.body)
	}

	expectStatus(t, patch(bob.id.String(), map[string]bool{"disabled": false}, true), 200, "enable bob")
	// Enabling does not resurrect revoked credentials; bob signs in again.
	expectStatus(t, e.as(bob, http.MethodGet, "/api/v1/me", nil), 401, "bob's revoked token after enable")
	if n := e.count("SELECT count(*) FROM users WHERE id = $1 AND disabled_at IS NULL", bob.id); n != 1 {
		t.Fatal("bob still disabled")
	}
	actions := e.auditActions()
	for _, want := range []string{"user.disable", "user.enable"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}
