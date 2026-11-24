# Nook

Nook is a self-hosted private cloud for a team's internal tools. A developer
runs `nook deploy` in a folder with a Dockerfile; Nook builds it, runs it on
one of the team's own servers and serves it at a private URL such as
`https://leave-tracker.apps.example.com`, which only the people the owner
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

The agent, gateway, deployments and dashboard come later; see
[docs/architecture.md](docs/architecture.md) for the full design.

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

Developer tools (golangci-lint, govulncheck, goose, sqlc, GoReleaser) are installed at pinned
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

Stop the server with Ctrl-C (it drains in-flight requests), and the stack with
`make dev-down` (data volumes are kept). To use Google instead of Dex, see
[docs/learn/01-identity.md](docs/learn/01-identity.md#switching-from-dex-to-google).

Run `make help` for every target. The common ones:

```sh
make test               # unit tests with the race detector
make test-integration   # + integration tests against real Postgres/Redis (Docker)
make lint               # golangci-lint
make vuln               # govulncheck
make docker-build       # nook-server image for linux/amd64 and linux/arm64
make docker-run         # run that image against the dev stack on 127.0.0.1:8081
make sqlc               # regenerate internal/store after changing SQL
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

## Documentation

- [docs/architecture.md](docs/architecture.md): components, data stores, request flows
- [docs/decisions/](docs/decisions/): architecture decision records
- [docs/learn/](docs/learn/): plain-English notes for each stage
- [CLAUDE.md](CLAUDE.md): engineering rules and repository layout
