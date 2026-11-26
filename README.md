# Nook

Nook is a self-hosted private cloud for a team's internal tools. A developer
runs `nook deploy` in a folder with a Dockerfile; Nook builds it, runs it on
one of the team's own servers and serves it at a private URL such as
`https://leave-tracker--acme.apps.example.com`, which only the people the owner
granted access to can open (they sign in with Google through OpenID Connect).
Idle apps are stopped and woken again on the next request.

Nook is built in stages. So far:

1. **Foundation**: the `nook-server` control plane with configuration,
   logging, metrics, health checks, migrations and graceful shutdown, plus
   the dev stack, tooling and CI.
2. **Identity and access**: sign-in through any OpenID Connect provider
   (Google, or Dex in development), invite-only admission, workspaces with
   owner/admin/member roles, API tokens, the `nook` CLI with device-flow
   login, an append-only audit log and the REST API v1
   ([api/openapi.yaml](api/openapi.yaml)).
3. **Worker nodes**: `nook-agent` joins a machine with a single-use token
   and a pinned CA hash, then keeps a mutually authenticated gRPC stream to
   the control plane with heartbeats, short-lived auto-renewed certificates
   and live node inspection; failure detection (ready → suspect → dead)
   runs on one elected leader among control-plane instances; admins manage
   nodes, join tokens and users from the CLI.
4. **Apps and builds**: `nook deploy` packs a project folder (honoring
   `.dockerignore` and `.nookignore`), uploads it straight to S3-compatible
   storage with a presigned URL, and follows the live build log while a
   worker node builds the image with rootless BuildKit in a locked-down
   container and pushes it to Nook's private registry, where it is stored
   by digest.
5. **Running apps**: every successful build is released: the scheduler
   places the app on a node, the agent runs it in a locked-down container
   (own network, no capabilities, limits, egress firewall), and a health
   check gates the switch, so the previous version serves until the new
   one is healthy and a failed release changes nothing. Crashes restart
   with backoff; crash loops are reported. `nook env` manages variables
   and secrets (encrypted at rest; changes release without a rebuild),
   `nook logs --follow` streams output, `nook rollback` and
   `nook apps stop/start` do what they say.

6. **The gateway**: `nook-gateway`, the only public entry point, serves
   every app at `https://<app>--<workspace>.<apps domain>` (TLS from Let's
   Encrypt on demand, your own certificate, or a TLS proxy in front).
   Visitors of private apps sign in through one auth host with the same
   identity provider (no Nook account needed); `nook access` chooses who
   may open an app (workspace members, admins plus granted emails, or
   anyone), and the app receives the visitor's email in `X-Nook-Email`.
   WebSockets and server-sent events pass through; app ports accept
   connections only from the gateways.

Sleeping apps, moving apps between nodes and the dashboard come later.

## Prerequisites

Nook is developed on Windows 11 with **WSL2 (Ubuntu)**, or on Linux/macOS.
Run every command inside WSL, from a checkout on the Linux file system (for
example `~/nook`, not `/mnt/c/...`, which is much slower).

| Tool | Version | Notes |
|------|---------|-------|
| Go | 1.27.4 | Recorded in `go.mod` |
| Docker | Docker Desktop with WSL integration enabled for your distro | Needs the containerd image store (the default) for multi-arch `--load` |
| GNU make, git, curl | any recent | `sudo apt-get install -y make git curl` |
| gcc | any recent | Required by Go's race detector and by sqlc: `sudo apt-get install -y build-essential` |

Developer tools (golangci-lint, govulncheck, goose, sqlc, GoReleaser, buf and the protoc plugins) are installed at pinned
versions into `./bin` by the Makefile on first use; nothing is installed
globally.

## Quick start

```sh
make dev-up          # creates/updates .env, starts Postgres, Redis, MinIO and Dex
make run-server      # builds and runs nook-server on http://localhost:8080
```

In another terminal:

```sh
curl -i http://127.0.0.1:8080/healthz   # liveness: is the process up?
curl -i http://127.0.0.1:8080/readyz    # readiness: are Postgres and Redis reachable?
curl -s http://127.0.0.1:8080/metrics | grep '^nook_'
```

Open <http://localhost:8080> and sign in through Dex, the development
identity provider. Its three test users have random passwords in `.env`:

| User | Password variable | Can sign in? |
|------|-------------------|--------------|
| `alice@nook.test` | `DEX_ALICE_PASSWORD` | yes: allowed domain, and instance admin |
| `bob@partner.test` | `DEX_BOB_PASSWORD` | only after someone invites him |
| `mallory@outside.test` | `DEX_MALLORY_PASSWORD` | never (shows "not invited") |

Then use the CLI (it opens your browser to approve the login):

```sh
go run ./cmd/nook login http://localhost:8080
go run ./cmd/nook whoami
go run ./cmd/nook workspace create acme --name "Acme"
go run ./cmd/nook token create --name ci     # for scripts; shown once
go run ./cmd/nook logout                     # revokes the CLI's token
```

Add this machine as a worker node (alice is an instance admin):

```sh
make build
bin/nook node join-token create          # prints the complete join command
export NOOK_AGENT_STATE_DIR=$HOME/.nook-agent   # default: /var/lib/nook-agent
bin/nook-agent join --server localhost:9443 --token nook_join_… --ca-hash sha256:…
bin/nook-agent run
bin/nook node list                       # ready, with CPU, memory, disk and containers
bin/nook node inspect <name>             # live Docker information from the agent
```

Then deploy an example app. `make run-agent` runs the agent with the
development settings from `.env` (state in `.nook-dev/agent`, apps
published on 127.0.0.1, builds on the filtered `nook-builds` network with
the dev registry allowed, exactly as in production):

```sh
bin/nook node join-token create          # prints the join command
bin/nook-agent join --state-dir .nook-dev/agent --server 127.0.0.1:9443 --token nook_join_… --ca-hash sha256:…
make run-agent
```

Run the gateway too (apps at `http://<app>--<workspace>.apps.localhost:8090`;
browsers resolve `*.localhost` to this machine):

```sh
make run-gateway
```

```sh
cd examples/hello-go
../../bin/nook deploy                     # pack, upload, build, release; ends with the app's URL
../../bin/nook open hello-go              # sign in as alice@nook.test: "Signed in as alice@nook.test"
../../bin/nook access grant hello-go bob@partner.test   # let someone else in (by email)
../../bin/nook access set hello-go --mode public        # or: workspace (default), restricted
../../bin/nook apps info hello-go         # URL, access, live deployment, instance, restarts
../../bin/nook env set hello-go GREETING=hi        # releases the change without a rebuild
../../bin/nook logs hello-go --follow
../../bin/nook rollback hello-go
```

`nook init` writes a `nook.toml` for your own project (port, health check
path, memory, CPU, startup timeout, read-only root file system);
`nook apps`, `nook deployments`, `nook build-logs` and `nook env` cover
the rest. Secrets: `nook env set <app> KEY=- --secret` reads the value
from standard input (workspace admins and owners only). The master key
lives in `.nook-dev/secrets.key` (created by `make dev-up`; back it up
apart from the database in production).

Stop the server with Ctrl-C (it drains in-flight requests), and the stack with
`make dev-down` (data volumes are kept). To use Google instead of Dex,
register a web OAuth client whose redirect URI is `NOOK_PUBLIC_URL` +
`/auth/callback`, then set `NOOK_OIDC_ISSUER_URL=https://accounts.google.com`
and the client ID and secret (see `.env.example`).

Run `make help` for every target. The common ones:

```sh
make test               # unit tests with the race detector
make test-integration   # + integration tests against real Postgres/Redis (Docker; no internet needed)
make test-e2e-internet  # end-to-end tests that need the internet (CI: nightly and on version tags)
make lint               # golangci-lint
make vuln               # govulncheck
make docker-build       # nook-server, nook-agent and nook-gateway images for linux/amd64 and linux/arm64
make docker-run         # run all three images against the dev stack (API on 127.0.0.1:8081); make docker-stop
make sqlc               # regenerate internal/store after changing SQL
make proto              # regenerate proto/ after changing a .proto file
make openapi-lint       # validate api/openapi.yaml
make release-snapshot   # build the CLI for every OS/arch into dist/
```

## Configuration

`nook-server` is configured only through environment variables; every one is
documented in [.env.example](.env.example). `make env` copies it to `.env`
and, when the example gains variables, appends them to your existing
`.env` without changing your values. The CLI reads
`~/.config/nook/config.json` (written with mode 0600; looser permissions are
refused) or, for CI, `NOOK_SERVER` and `NOOK_TOKEN`. Invalid configuration stops the
process at startup with a list of every problem. Secrets can also be supplied
as files: `NOOK_POSTGRES_URL_FILE=/run/secrets/pg-url`.

### Networks between nodes

The gateway forwards visitors' requests to app containers over plain HTTP
(the identity headers it adds and the cookies apps set travel in clear
text on that hop). **Multi-node installations must therefore connect the
gateways, control planes and worker nodes over a private network** — a
cloud VPC, or WireGuard tunnels between the machines — and set on every
worker:

- `NOOK_AGENT_ADVERTISE_ADDR` to the node's address on that network. The
  agent refuses a public address (anything but loopback, RFC 1918, IPv6
  ULA or 100.64.0.0/10, the range WireGuard meshes such as Tailscale use)
  unless `NOOK_AGENT_ALLOW_PUBLIC_ADVERTISE_ADDR=true`, and warns at every
  start when that override lets one through.
- `NOOK_AGENT_GATEWAY_ADDRS` to the gateways' addresses, so app ports
  accept connections from the gateways only.

TLS on this hop (terminated by the agent with its node certificate) is
possible future work.

### Running the images

`make docker-run` starts the three images built by `make docker-build`
(for this machine only: `make docker-build PLATFORMS=linux/amd64`)
against the dev stack, with the settings from `.env` rewritten per
container into env files under `.nook-dev/docker/` (mode 0600). Stop
`make run-server`, `make run-agent` and `make run-gateway` first: the
agent container runs this machine's dev node and the gateway takes its
ports. The API is on 127.0.0.1:8081 (use `NOOK_SERVER` and `NOOK_TOKEN`),
apps on the usual `*.apps.localhost:8090` URLs; apps placed before need a
new deployment (`nook env set`) to move to the containers' address.
Limits of this setup: browser sign-in through Dex needs `make run-server`
(Dex is `localhost:5556` to the browser but not to the container), and
builds need `make run-agent` (presigned storage URLs must be reachable by
both the CLI and the agent). On Docker Desktop, published ports are
forwarded by Docker Desktop's own proxy, which the agent's gateway-only
rule cannot see, so other containers can reach app ports there; on Linux
servers the rule applies.

## Troubleshooting

- **`make dev-up` says a port is not published.** Another program owns that
  host port: a native Windows PostgreSQL on 5432 is common, and so is another
  project's Redis on 6379. Set a free port with `POSTGRES_PORT`,
  `REDIS_PORT`, `MINIO_API_PORT` or `MINIO_CONSOLE_PORT` in `.env`, then run
  `make dev-down dev-up`. The URLs in `.env` follow automatically. Dex uses
  `DEX_PORT` (5556); if you change it, NOOK_OIDC_ISSUER_URL follows too.
- **`-race requires cgo`.** Install gcc: `sudo apt-get install -y build-essential`.
- **Integration tests cannot reach Docker.** In Docker Desktop, enable
  *Settings → Resources → WSL integration* for your distro, and make sure
  `docker ps` works without `sudo`. testcontainers-go uses the default socket
  `/var/run/docker.sock`; no extra configuration is needed.
