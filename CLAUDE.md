# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository. Nook is a
self-hosted private cloud for internal tools; see `docs/architecture.md` for
the full system map.

## Start of every stage

Read, in order: this file, `docs/architecture.md`, and the latest file in
`docs/learn/`. Then check `docs/decisions/` for ADRs touching your area.

## Engineering rules

1. **Production quality only.** No TODO/FIXME, stubs, fake data, mocked
   behavior, commented-out code or placeholder files in committed code. If
   something belongs to a later stage, do not create it at all.
2. **Read before building** (see above).
3. **Keep the repository layout below.** When a new package is needed, add it
   to the layout map with a one-line purpose.
4. **Code:** small focused packages, files ideally under ~300 lines, clear
   names, comments explain *why* rather than *what*, every exported identifier
   documented. Wrap errors with context using `%w`. No panics outside `main`.
   Every network/disk/DB call takes a context with a timeout.
5. **Security:** validate and bound all external input (sizes, lengths,
   formats). SQL only through parameterized queries (sqlc from stage 2).
   Secrets only from environment variables or files, never logged, never
   committed. Compare secrets in constant time. Containers run as non-root
   with no-new-privileges and dropped capabilities. TLS everywhere outside
   localhost. Pin dependency and image versions. Run govulncheck.
6. **Testing:** every behavior has tests. Integration tests use real
   Postgres/Redis via testcontainers-go and carry the `//go:build integration`
   tag. `go test -race` must pass. No sleep-based timing in tests; poll with
   deadlines.
7. **Observability:** structured JSON logs via `log/slog` with a `request_id`
   on every request; Prometheus metrics for every component; liveness and
   readiness endpoints.
8. **Every binary:** fail fast on invalid config, graceful shutdown on
   SIGINT/SIGTERM, a `--version` flag printing version, commit and build date
   (set via ldflags).
9. **Dependencies:** prefer the standard library. Approved stack: Gin,
   pgx/v5, sqlc, goose, go-redis/v9, gRPC + buf, Cobra,
   prometheus/client_golang, testcontainers-go, caarlos0/env. Any other
   dependency needs a one-line justification in that stage's learn doc.
10. **Documentation:** each stage adds `docs/learn/NN-<stage>.md` in plain
    English (what was built, how it works, why, how to run it, 5–8 interview
    questions with model answers), plus an ADR in `docs/decisions/` for any
    significant decision.
11. **Verify before reporting:** run lint, all tests, the vulnerability check
    and a manual end-to-end check, and show the real output. If something
    fails, fix it. Never skip, weaken or disable a check to make it pass.
12. **Git:** conventional commit messages, one or a few logical commits per
    stage. Never commit secrets. Do not push.

## Commands

All commands run inside WSL2 (Ubuntu) or Linux/macOS. `make help` lists all.

| Task | Command |
|------|---------|
| Start Postgres/Redis/MinIO | `make dev-up` (creates `.env` with random secrets on first run) |
| Run the control plane | `make run-server` |
| Unit tests (race) | `make test` |
| Unit + integration tests | `make test-integration` (needs Docker) |
| Lint / format | `make lint` / `make fmt` |
| Vulnerability scan | `make vuln` |
| New migration | `make migrate-new name=add_users` |
| Multi-arch image | `make docker-build`, then `make docker-run` |

## Conventions

- **Configuration** is environment variables named `NOOK_<AREA>_<NAME>`,
  parsed into the `Config` struct owned by the package that uses it
  (`postgres.Config`, `httpserver.Config`, ...), validated in a `Validate`
  method, and composed per binary (`server.Config`). Every variable is
  documented in `.env.example`. Any `NOOK_X` may be supplied as `NOOK_X_FILE`;
  never name a path variable `*_FILE` (use `*_PATH`).
- **Secrets** in config use `config.Secret`, which redacts itself in every
  output path; call `Reveal()` only where a library needs the plaintext.
- **Outside development** (`NOOK_ENV=staging|production`) every connection
  must use TLS; `server.Config.Validate` enforces it. Keep that rule when
  adding new connections.
- **HTTP errors** use the envelope `{"error":{"code","message","request_id"}}`
  via `httpserver.AbortWithError`.
- **Metrics** live in a per-binary `prometheus.Registry` (never the global
  one), prefixed `nook_`. Label values must be bounded: route templates, not
  raw paths.
- **Migrations** are goose SQL files in `migrations/`, embedded into the
  binary and applied at startup under a Postgres advisory lock. Never edit a
  committed migration; add a new one. Domain tables arrive with the code that
  uses them.
- **Images** are pinned as `tag@sha256:digest`. Integration tests use the same
  Postgres/Redis images as the compose file (`internal/testinfra`; a test
  enforces this).
- **Tests** never sleep to wait; they poll with a deadline or synchronize on
  channels.

## Repository layout

Directories marked *(planned)* do not exist yet; create them in the stage
that needs them.

```
nook/
├── CLAUDE.md                  # this file: rules + layout map
├── README.md                  # what Nook is, dev quick start
├── Makefile                   # every common task; `make help` lists them
├── go.mod / go.sum            # single module github.com/the-asmit/nook
├── .golangci.yml              # linter configuration (golangci-lint v2)
├── .editorconfig .gitignore .dockerignore .env.example
├── .github/
│   ├── workflows/ci.yml       # lint, race tests, integration tests, govulncheck, multi-arch docker build
│   └── dependabot.yml         # keeps pinned Go modules, actions and images current
├── cmd/                       # one folder per binary; main.go only wires dependencies
│   ├── nook-server/           # control plane entry point
│   ├── nook/                  # (planned) CLI
│   ├── nook-agent/            # (planned) worker agent
│   └── nook-gateway/          # (planned) gateway
├── internal/
│   ├── platform/              # shared infrastructure used by every binary
│   │   ├── config/            # env loading, *_FILE secrets, Secret type, Environment, validators
│   │   ├── logging/           # slog JSON logger, request ID in context
│   │   ├── postgres/          # pgx pool, advisory-locked goose migrations, pool metrics
│   │   ├── redis/             # go-redis client setup
│   │   ├── metrics/           # Prometheus registry + build info + /metrics handler
│   │   ├── health/            # dependency probes for /readyz and startup waits
│   │   └── httpserver/        # server lifecycle, graceful shutdown, common Gin middleware
│   ├── server/                # control plane: config + startup/shutdown wiring
│   │   └── api/               # Gin router, middleware order, handlers
│   ├── version/               # build info set via ldflags
│   ├── testinfra/             # testcontainers helpers (integration build tag only)
│   ├── store/                 # (planned) sqlc queries + generated code
│   ├── auth/                  # (planned) OIDC, sessions, API tokens
│   ├── queue/                 # (planned) Redis-backed job queue
│   ├── scheduler/             # (planned) placement + failover
│   ├── agent/                 # (planned) worker agent logic
│   ├── gateway/               # (planned) gateway logic
│   └── cli/                   # (planned) CLI commands
├── migrations/                # goose SQL migrations, embedded into the binary by migrations.go
├── proto/                     # (planned) gRPC definitions
├── web/                       # (planned) React dashboard
├── deploy/
│   ├── compose/docker-compose.dev.yml   # Postgres, Redis, MinIO for development
│   └── docker/nook-server.Dockerfile    # multi-stage, distroless, non-root
├── test/e2e/                  # (planned) end-to-end tests
└── docs/
    ├── architecture.md        # the full system map
    ├── decisions/             # ADRs 0001-*.md ...
    └── learn/                 # plain-English stage notes
```
