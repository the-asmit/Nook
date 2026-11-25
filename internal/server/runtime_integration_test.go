//go:build integration

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// TestRolloutReplacesTheOldVersionAfterDrain releases two versions: the
// second goes live only once healthy, the first keeps serving until the
// switch and is stopped and removed after the drain period.
func TestRolloutReplacesTheOldVersionAfterDrain(t *testing.T) {
	r := startRuntimeEnv(t, map[string]string{"NOOK_ROLLOUT_DRAIN": "3s"})
	r.newRuntimeApp(r.alice, r.ws, "web", nil)

	n1 := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n1)
	first := r.appBase(r.alice, r.ws, "web")
	if code, body := get(first + "/"); code != http.StatusOK || !strings.Contains(body, "deployment 1") {
		t.Fatalf("first version: %d %q", code, body)
	}

	n2 := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n2)
	second := r.appBase(r.alice, r.ws, "web")
	if second == first {
		t.Fatalf("the new version reuses the old address %s", second)
	}
	if code, body := get(second + "/"); code != http.StatusOK || !strings.Contains(body, "deployment 2") {
		t.Fatalf("second version: %d %q", code, body)
	}
	// Draining: the old instance still answers right after the switch.
	if code, _ := get(first + "/healthz"); code != http.StatusOK {
		t.Fatalf("the old version stopped before its drain period: %d", code)
	}
	eventually(t, 30*time.Second, "the old instance to stop", func() bool {
		return r.count("SELECT count(*) FROM app_instances i JOIN deployments d ON d.id = i.deployment_id WHERE d.number = 1 AND i.state = 'stopped'") == 1
	})
	if code, _ := get(first + "/healthz"); code == http.StatusOK {
		t.Fatal("the old version still answers after it was stopped")
	}
	if d := r.deployment(r.alice, r.ws, "web", n1); d.Status != "superseded" {
		t.Fatalf("old deployment is %s, want superseded", d.Status)
	}
	if a := r.app(r.alice, r.ws, "web"); a.Health != "running" || a.LiveDeployment == nil || *a.LiveDeployment != n2 {
		t.Fatalf("app %+v", a)
	}
	_, appID := r.appIDs(r.ws, "web")
	if n := countContainers(t, "nook.app="+appID.String()); n != 1 {
		t.Fatalf("%d app containers on the node, want 1", n)
	}
}

// countContainers counts containers (running or not) carrying a label.
func countContainers(t *testing.T, label string) int {
	t.Helper()
	list, err := dockerClient(t).ContainerList(context.Background(), client.ContainerListOptions{
		All: true, Filters: client.Filters{}.Add("label", label),
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(list.Items)
}

// dockerClient talks to the local Docker engine.
func dockerClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestFailedHealthCheckKeepsTheOldVersion releases a version whose health
// check fails: the deployment fails with its startup output kept, and the
// previous version keeps answering.
func TestFailedHealthCheckKeepsTheOldVersion(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", map[string]any{"startup_timeout_seconds": 4})
	n1 := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n1)
	base := r.appBase(r.alice, r.ws, "web")

	res := r.setEnv(r.alice, r.ws, "web", map[string]string{"TESTAPP_MODE": "unhealthy"}, false)
	n2 := envDeployment(t, res)
	d := r.waitStatus(r.alice, r.ws, "web", n2, 2*time.Minute, "failed", "live")
	if d.Status != "failed" || !strings.Contains(d.FailureReason, "health check GET /healthz did not answer 2xx within 4s") ||
		!strings.Contains(d.FailureReason, "HTTP 500") {
		t.Fatalf("deployment %+v", d)
	}
	var detail struct {
		Instance struct {
			State      string `json:"state"`
			StartupLog string `json:"startup_log"`
		} `json:"instance"`
	}
	r.as(r.alice, http.MethodGet, appURL(r.ws, "web")+"/deployments/"+itoa(n2), nil).json(t, &detail)
	if detail.Instance.State != "failed" || !strings.Contains(detail.Instance.StartupLog, `mode "unhealthy"`) {
		t.Fatalf("instance %+v", detail.Instance)
	}
	if log := r.buildLog(r.alice, r.ws, "web", n2); !strings.Contains(log, "the previous version keeps serving") {
		t.Fatalf("deployment log:\n%s", log)
	}
	if code, body := get(base + "/"); code != http.StatusOK || !strings.Contains(body, "deployment 1") {
		t.Fatalf("the old version stopped answering: %d %q", code, body)
	}
	if a := r.app(r.alice, r.ws, "web"); a.LiveDeployment == nil || *a.LiveDeployment != n1 || a.Health != "running" {
		t.Fatalf("app %+v", a)
	}
	_, appID := r.appIDs(r.ws, "web")
	eventually(t, 30*time.Second, "the failed container to be removed", func() bool {
		return countContainers(t, "nook.app="+appID.String()) == 1
	})
}

// TestStartupTimeoutIsHonored: an app that never listens fails after its
// own startup timeout, not the default.
func TestStartupTimeoutIsHonored(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "slow", map[string]any{"startup_timeout_seconds": 3})
	expectStatus(t, r.setEnv(r.alice, r.ws, "slow", map[string]string{"TESTAPP_MODE": "slow"}, false), http.StatusOK, "set env")
	n := r.release(r.ws, "slow")
	start := time.Now()
	d := r.waitStatus(r.alice, r.ws, "slow", n, 2*time.Minute, "failed", "live")
	if d.Status != "failed" || !strings.Contains(d.FailureReason, "within 3s") {
		t.Fatalf("deployment %+v", d)
	}
	if took := time.Since(start); took > 45*time.Second {
		t.Fatalf("the rollout took %s for a 3s startup timeout", took)
	}
	if a := r.app(r.alice, r.ws, "slow"); a.LiveDeployment != nil {
		t.Fatalf("nothing should be live: %+v", a)
	}
}

// TestEnvChangesAndSecrets: variables and secrets reach the container
// through a new deployment of the same image (no build), secrets are
// encrypted at rest and never returned, logged or audited, and only
// admins may set or remove them.
func TestEnvChangesAndSecrets(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	owner := r.alice
	member := r.newUser("member@nook.test")
	expectStatus(t, r.as(owner, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Team", "slug": "team"}), 201, "create workspace")
	expectStatus(t, r.as(owner, http.MethodPost, "/api/v1/workspaces/team/invitations", map[string]string{"email": member.email, "role": "member"}), 201, "invite")
	r.newUserSignIn(member.email)
	r.newRuntimeApp(owner, "team", "web", nil)
	n1 := r.release("team", "web")
	r.waitLive(owner, "team", "web", n1)

	const secretValue = "s3cr3t-value-that-must-not-leak"
	t.Run("member sets a plain variable", func(t *testing.T) {
		res := r.setEnv(member, "team", "web", map[string]string{"GREETING": "hello there"}, false)
		expectStatus(t, res, http.StatusOK, "set GREETING")
		n := envDeployment(t, res)
		r.waitLive(owner, "team", "web", n)
		if _, body := get(r.appBase(owner, "team", "web") + "/env?k=GREETING"); body != "hello there" {
			t.Fatalf("GREETING = %q", body)
		}
	})
	t.Run("member cannot touch secrets", func(t *testing.T) {
		expectStatus(t, r.setEnv(member, "team", "web", map[string]string{"API_KEY": "x"}, true), http.StatusForbidden, "member sets secret")
	})
	var secretDeployment int32
	t.Run("owner sets a secret", func(t *testing.T) {
		res := r.setEnv(owner, "team", "web", map[string]string{"API_KEY": secretValue}, true)
		expectStatus(t, res, http.StatusOK, "set secret")
		if strings.Contains(res.body, secretValue) {
			t.Fatal("the response contains the secret")
		}
		secretDeployment = envDeployment(t, res)
		r.waitLive(owner, "team", "web", secretDeployment)
		if _, body := get(r.appBase(owner, "team", "web") + "/env?k=API_KEY"); body != secretValue {
			t.Fatalf("API_KEY in the container = %q", body)
		}
		if _, body := get(r.appBase(owner, "team", "web") + "/env?k=PORT"); body != "8080" {
			t.Fatalf("PORT = %q", body)
		}
	})
	t.Run("members cannot overwrite or remove the secret", func(t *testing.T) {
		expectStatus(t, r.setEnv(member, "team", "web", map[string]string{"API_KEY": "plain"}, false), http.StatusForbidden, "overwrite secret")
		expectStatus(t, r.as(member, http.MethodDelete, appURL("team", "web")+"/env/API_KEY", nil), http.StatusForbidden, "unset secret")
	})
	t.Run("validation", func(t *testing.T) {
		expectStatus(t, r.setEnv(owner, "team", "web", map[string]string{"PORT": "1"}, false), http.StatusBadRequest, "reserved PORT")
		expectStatus(t, r.setEnv(owner, "team", "web", map[string]string{"NOOK_X": "1"}, false), http.StatusBadRequest, "reserved prefix")
		expectStatus(t, r.setEnv(owner, "team", "web", map[string]string{"1BAD": "1"}, false), http.StatusBadRequest, "bad name")
		expectStatus(t, r.setEnv(owner, "team", "web", map[string]string{"BIG": strings.Repeat("x", 33<<10)}, false), http.StatusBadRequest, "too large")
	})
	t.Run("secrets are masked, encrypted and never logged", func(t *testing.T) {
		res := r.as(member, http.MethodGet, appURL("team", "web")+"/env", nil)
		expectStatus(t, res, http.StatusOK, "list")
		if strings.Contains(res.body, secretValue) || !strings.Contains(res.body, `"key":"API_KEY","value":null,"secret":true`) ||
			!strings.Contains(res.body, `"value":"hello there"`) {
			t.Fatalf("list: %s", res.body)
		}
		for _, q := range []string{
			"SELECT count(*) FROM app_env WHERE position($1::bytea IN value) > 0",
			"SELECT count(*) FROM env_snapshot_vars WHERE position($1::bytea IN value) > 0",
		} {
			if n := r.count(q, []byte(secretValue)); n != 0 {
				t.Fatalf("plaintext found in the database: %s", q)
			}
		}
		if n := r.count("SELECT count(*) FROM audit_log WHERE metadata::text LIKE '%' || $1 || '%'", secretValue); n != 0 {
			t.Fatal("the secret is in the audit log")
		}
		if strings.Contains(r.logs.String(), secretValue) {
			t.Fatal("the secret is in the server logs")
		}
		if log := r.buildLog(owner, "team", "web", secretDeployment); strings.Contains(log, secretValue) {
			t.Fatal("the secret is in the deployment log")
		}
		d := r.deployment(owner, "team", "web", secretDeployment)
		if len(d.Builds) != 0 {
			t.Fatalf("an environment change rebuilt the image: %+v", d.Builds)
		}
	})
	t.Run("owner removes the secret", func(t *testing.T) {
		res := r.as(owner, http.MethodDelete, appURL("team", "web")+"/env/API_KEY", nil)
		expectStatus(t, res, http.StatusOK, "unset")
		r.waitLive(owner, "team", "web", envDeployment(t, res))
		if code, _ := get(r.appBase(owner, "team", "web") + "/env?k=API_KEY"); code != http.StatusNotFound {
			t.Fatalf("API_KEY still set: %d", code)
		}
	})
}

// TestRollbackUsesTheDeploymentsEnvironment rolls back to a deployment
// with the environment it had, not the current one.
func TestRollbackUsesTheDeploymentsEnvironment(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	expectStatus(t, r.setEnv(r.alice, r.ws, "web", map[string]string{"A": "1"}, false), http.StatusNotFound, "env of a missing app")
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	expectStatus(t, r.setEnv(r.alice, r.ws, "web", map[string]string{"GREETING": "first"}, false), http.StatusOK, "set")
	n1 := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n1)
	n2 := envDeployment(t, r.setEnv(r.alice, r.ws, "web", map[string]string{"GREETING": "second"}, false))
	r.waitLive(r.alice, r.ws, "web", n2)
	if _, body := get(r.appBase(r.alice, r.ws, "web") + "/env?k=GREETING"); body != "second" {
		t.Fatalf("GREETING = %q", body)
	}

	res := r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/rollback", map[string]any{})
	expectStatus(t, res, http.StatusCreated, "rollback")
	var rb struct {
		Number     int32  `json:"number"`
		Kind       string `json:"kind"`
		RollbackTo *int32 `json:"rollback_to"`
	}
	res.json(t, &rb)
	if rb.Kind != "rollback" || rb.RollbackTo == nil || *rb.RollbackTo != n1 {
		t.Fatalf("rollback deployment %+v", rb)
	}
	r.waitLive(r.alice, r.ws, "web", rb.Number)
	if _, body := get(r.appBase(r.alice, r.ws, "web") + "/env?k=GREETING"); body != "first" {
		t.Fatalf("after the rollback GREETING = %q, want the snapshot's value", body)
	}
	if d := r.deployment(r.alice, r.ws, "web", n2); d.Status != "rolled_back" {
		t.Fatalf("the replaced deployment is %s, want rolled_back", d.Status)
	}
	// The current variables are unchanged by a rollback.
	if res := r.as(r.alice, http.MethodGet, appURL(r.ws, "web")+"/env", nil); !strings.Contains(res.body, `"value":"second"`) {
		t.Fatalf("env after rollback: %s", res.body)
	}
	expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/rollback", map[string]any{"to": rb.Number}), http.StatusConflict, "roll back to the live one")
	expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/rollback", map[string]any{"to": 99}), http.StatusNotFound, "missing target")
}
