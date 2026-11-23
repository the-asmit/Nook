# Nook

Nook is a self-hosted private cloud for a team's internal tools. A developer
runs `nook deploy` in a folder with a Dockerfile; Nook builds it, runs it on
one of the team's own servers and serves it at a private URL such as
`https://leave-tracker.apps.example.com`, which only the people the owner
granted access to can open (they sign in with Google through OpenID Connect).
Idle apps are stopped and woken again on the next request.

Nook is built in stages. **This stage is the foundation:** the `nook-server`
control plane runs with configuration, logging, metrics, health checks,
database migrations and graceful shutdown, plus the development stack,
tooling, CI and docs. The CLI, agent, gateway and dashboard come later; see
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
| gcc | any recent | Required by Go's race detector: `sudo apt-get install -y build-essential` |

Developer tools (golangci-lint, govulncheck, goose) are installed at pinned
versions into `./bin` by the Makefile on first use; nothing is installed
globally.

## Quick start

```sh
make dev-up          # creates .env with random passwords, starts Postgres, Redis, MinIO
make run-server      # builds and runs nook-server on 127.0.0.1:8080
```

In another terminal:

```sh
curl -i http://127.0.0.1:8080/healthz   # liveness: is the process up?
curl -i http://127.0.0.1:8080/readyz    # readiness: are Postgres and Redis reachable?
curl -s http://127.0.0.1:8080/metrics | grep '^nook_'
```

Stop the server with Ctrl-C (it drains in-flight requests), and the stack with
`make dev-down` (data volumes are kept).

Run `make help` for every target. The common ones:

```sh
make test               # unit tests with the race detector
make test-integration   # + integration tests against real Postgres/Redis (Docker)
make lint               # golangci-lint
make vuln               # govulncheck
make docker-build       # nook-server image for linux/amd64 and linux/arm64
make docker-run         # run that image against the dev stack on 127.0.0.1:8081
```

## Configuration

`nook-server` is configured only through environment variables; every one is
documented in [.env.example](.env.example). Invalid configuration stops the
process at startup with a list of every problem. Secrets can also be supplied
as files: `NOOK_POSTGRES_URL_FILE=/run/secrets/pg-url`.

## Troubleshooting

- **`make dev-up` says a port is not published.** Another program owns that
  host port: a native Windows PostgreSQL on 5432 is common, and so is another
  project's Redis on 6379. Set a free port with `POSTGRES_PORT`,
  `REDIS_PORT`, `MINIO_API_PORT` or `MINIO_CONSOLE_PORT` in `.env`, then run
  `make dev-down dev-up`. The URLs in `.env` follow automatically.
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
