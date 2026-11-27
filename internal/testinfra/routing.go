//go:build integration

package testinfra

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// IPTablesImage ships iptables: the agent's default firewall image (a test
// in internal/agent keeps them equal).
const IPTablesImage = "registry.k8s.io/build-image/distroless-iptables:v0.9.6@sha256:33f27a340efd1f0a0341bd85755f1752af00b27debaf2f2876a3ef5dcc07f84a"

// routingScript adds (or removes) ACCEPT rules at the top of DOCKER-USER
// for traffic into and out of each bridge in $NOOK_BRIDGES, with the
// iptables backend Docker uses.
const routingScript = `set -eu
B=nft
case "$(iptables-nft-save -t filter 2>/dev/null || true)" in
  *":DOCKER"*) ;;
  *) case "$(iptables-legacy-save -t filter 2>/dev/null || true)" in *":DOCKER"*) B=legacy ;; esac ;;
esac
ipt=iptables-$B
if ! $ipt -S DOCKER-USER >/dev/null 2>&1; then echo "no DOCKER-USER chain"; exit 0; fi
for br in $NOOK_BRIDGES; do
  for dir in -i -o; do
    if [ "$NOOK_MODE" = add ]; then
      $ipt -C DOCKER-USER $dir "$br" -j ACCEPT 2>/dev/null || $ipt -I DOCKER-USER 1 $dir "$br" -j ACCEPT
    else
      while $ipt -D DOCKER-USER $dir "$br" -j ACCEPT 2>/dev/null; do :; done
    fi
  done
done
echo "routing $NOOK_MODE with $ipt: $NOOK_BRIDGES"
`

// AllowRouting makes the bridges of networks behave like a routed network:
// a native Docker engine (Docker 28 and later) drops traffic between
// bridge networks, which stand-ins for other hosts (a LAN, the registry,
// a metadata service) need, while Docker Desktop lets it through. The
// rules sit at the top of DOCKER-USER, so a Nook agent started afterwards
// still filters this traffic first (its jump is inserted above them). The
// returned function removes them.
func AllowRouting(ctx context.Context, networks ...string) (func(), error) {
	d, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var bridges []string
	for _, name := range networks {
		nw, err := d.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
		if err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("inspect network %s: %w", name, err)
		}
		br := nw.Network.Options["com.docker.network.bridge.name"]
		if br == "" {
			br = "br-" + nw.Network.ID[:12] // Docker's name for a user-defined bridge
		}
		bridges = append(bridges, br)
	}
	run := func(ctx context.Context, mode string) error {
		if _, err := d.ImageInspect(ctx, IPTablesImage); err != nil {
			pull, err := d.ImagePull(ctx, IPTablesImage, client.ImagePullOptions{})
			if err != nil {
				return fmt.Errorf("pull %s: %w", IPTablesImage, err)
			}
			if err := pull.Wait(ctx); err != nil {
				return fmt.Errorf("pull %s: %w", IPTablesImage, err)
			}
		}
		created, err := d.ContainerCreate(ctx, client.ContainerCreateOptions{
			Config: &container.Config{
				Image: IPTablesImage, User: "0:0", Entrypoint: []string{"/bin/sh", "-c", routingScript},
				Env: []string{"NOOK_MODE=" + mode, "NOOK_BRIDGES=" + strings.Join(bridges, " ")},
			},
			HostConfig: &container.HostConfig{
				NetworkMode: "host", CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN", "NET_RAW"},
				SecurityOpt: []string{"no-new-privileges:true"}, ReadonlyRootfs: true,
			},
		})
		if err != nil {
			return fmt.Errorf("create the routing helper: %w", err)
		}
		defer func() {
			_, _ = d.ContainerRemove(context.WithoutCancel(ctx), created.ID, client.ContainerRemoveOptions{Force: true})
		}()
		wait := d.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
		if _, err := d.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
			return fmt.Errorf("start the routing helper: %w", err)
		}
		var code int64
		select {
		case res := <-wait.Result:
			code = res.StatusCode
		case err := <-wait.Error:
			return fmt.Errorf("wait for the routing helper: %w", err)
		}
		if code != 0 {
			var out strings.Builder
			if logs, err := d.ContainerLogs(ctx, created.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}); err == nil {
				_, _ = stdcopy.StdCopy(&out, &out, logs)
				_ = logs.Close()
			}
			return fmt.Errorf("routing helper exited %d: %s", code, strings.TrimSpace(out.String()))
		}
		return nil
	}
	if err := run(ctx, "add"); err != nil {
		_ = d.Close()
		return nil, err
	}
	return func() {
		// Runs at cleanup, after the caller's context may have ended.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Minute)
		defer cancel()
		_ = run(ctx, "remove")
		_ = d.Close()
	}, nil
}
