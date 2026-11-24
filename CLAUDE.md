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
| Create/update `.env` | `make env` (adds new variables, never changes existing values) |
| Start Postgres/Redis/MinIO/Dex | `make dev-up` (runs `make env` first) |
| Run the control plane | `make run-server` |
| Unit tests (race) | `make test` |
| Unit + integration tests | `make test-integration` (needs Docker) |
| Lint / format | `make lint` / `make fmt` |
| Vulnerability scan | `make vuln` |
| New migration | `make migrate-new name=add_users` |
| Regenerate store / check it | `make sqlc` / `make sqlc-check` |
| Regenerate protobuf / check it | `make proto` / `make proto-check` |
| Lint protobuf / breaking changes | `make proto-lint` / `make proto-breaking` (against `main`) |
| Validate the OpenAPI spec | `make openapi-lint` |
| CLI release archives | `make release-snapshot` (into `dist/`) |
| Multi-arch images (server + agent) | `make docker-build`, then `make docker-run` |

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
- **SQL** lives in `internal/store/queries/*.sql`; run `make sqlc` after
  changing it or a migration and commit the generated `*.gen.go` (CI runs
  `make sqlc-check`). Remove queries nothing calls.
- **Tenant isolation**: resolve every workspace-scoped resource *through the
  caller's membership in the query* (`GetWorkspaceForMember`). A
  non-member gets 404 (`apperr.NotFound`), never 403; 403 is only for
  members lacking a role. Add a cross-tenant test for every new endpoint.
- **Domain errors** are `apperr` kinds (Invalid, Unauthenticated,
  Forbidden, NotFound, Conflict, RateLimited) with stable codes; handlers
  map them to HTTP. Anything else becomes a logged 500 with no details.
- **Audit**: every security-relevant change calls `audit.Record` inside the
  same `store.InTx` transaction. Action names are a contract: never rename.
  Metadata never holds secrets.
- **Secrets we issue** (sessions, API tokens, device codes) are 256-bit
  random values, shown once, stored only as SHA-256 hashes, never logged.
- **New API routes** must be added to `api/openapi.yaml`; a test fails
  otherwise. JSON bodies require `Content-Type: application/json`;
  cookie-authenticated state changes need Origin + `X-CSRF-Token`.
- **Protobuf** lives in `proto/nook/<area>/v<N>/`; run `make proto` after
  changing a `.proto` and commit the generated code (CI runs `proto-check`,
  `buf lint` and `buf breaking` against `main`). Never reuse or renumber a
  field; add a new version package for incompatible changes.
- **gRPC handlers** return deliberate status codes and never internal
  details: map errors through `agentlink`'s `toStatus` (unclassified errors
  are logged and become a bare `INTERNAL`). Every new stream or unary call
  from an agent is authenticated by certificate serial against the
  database, not by the TLS chain alone.
- **Singleton work** (anything only one control-plane instance may do) runs
  under `leader.Elector`, and its queries go through `leader.Session.Do` on
  the lock connection (fencing).
- **Node state** changes go through `nodes` (compare-and-set, a
  `node_events` row, a `nook:events:nodes` message); never update
  `nodes.status` directly. Times come from the control plane's clock
  (Redis `TIME`), never from agents.
- **Tests** never sleep to wait; they poll with a deadline or synchronize on
  channels. Integration tests in `internal/server` share one Postgres,
  Redis and Dex (`harness_integration_test.go`) and get a fresh database per
  test; the OIDC flow is always exercised against the real Dex.

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
├── buf.yaml / buf.gen.yaml    # buf module (proto/), lint + breaking rules, Go code generation (make proto)
├── .goreleaser.yaml           # builds the nook CLI for linux/darwin/windows × amd64/arm64
├── .github/
│   ├── workflows/ci.yml       # lint, sqlc/proto/OpenAPI checks, buf lint + breaking, race tests, integration tests, govulncheck, CLI + image builds
│   └── dependabot.yml         # keeps pinned Go modules, actions and images current
├── api/
│   ├── openapi.yaml           # OpenAPI 3.1 contract for every HTTP endpoint (tested against the router)
│   └── redocly.yaml           # lint rules for the spec (make openapi-lint)
├── cmd/                       # one folder per binary; main.go only wires dependencies
│   ├── nook-server/           # control plane entry point
│   ├── nook/                  # CLI entry point
│   ├── nook-agent/            # worker agent entry point: `join`, `run`, `version`
│   └── nook-gateway/          # (planned) gateway
├── internal/
│   ├── platform/              # shared infrastructure used by every binary
│   │   ├── config/            # env loading, *_FILE secrets, Secret type, Environment, validators, internal-host checks
│   │   ├── logging/           # slog JSON logger, request ID in context
│   │   ├── postgres/          # pgx pool, advisory-locked goose migrations, pool metrics
│   │   ├── redis/             # go-redis client setup
│   │   ├── metrics/           # Prometheus registry + build info + /metrics handler
│   │   ├── health/            # dependency probes for /readyz and startup waits
│   │   └── httpserver/        # server lifecycle, graceful shutdown, common Gin middleware
│   ├── server/                # control plane: config (incl. TLS rules) + startup/shutdown wiring
│   │   ├── api/               # Gin router, ops endpoints, /api/v1 JSON handlers
│   │   └── web/               # server-rendered pages: sign-in, sign-out, not-invited, device approval
│   ├── store/                 # sqlc: queries/*.sql, generated *.gen.go, sqlc.yaml, transactions
│   ├── apperr/                # classified domain errors (kind + stable code) mapped to HTTP by handlers
│   ├── audit/                 # append-only audit log entries, written in the change's transaction
│   ├── auth/                  # sessions, API tokens, CSRF, cookies, authentication middleware
│   ├── identity/              # OIDC provider, sign-in flow state, admission policy, first-login provisioning, user administration
│   ├── workspace/             # workspaces, memberships, invitations, role rules (tenant-scoped)
│   ├── device/                # OAuth 2.0 Device Authorization Grant for `nook login`
│   ├── ratelimit/             # fixed-window rate limits in Redis
│   ├── pki/                   # internal CA (shared PEM bundle), node + server certificates, CSR signing, CA pinning
│   ├── nodes/                 # node registry: join tokens, joining, renewal, heartbeats (Redis), states, events, failure detector
│   ├── leader/                # leader election with a Postgres session advisory lock, fenced sessions
│   ├── agentlink/             # control-plane gRPC server for agents (TLS 1.3, mTLS auth) + cross-instance command hub
│   ├── cli/                   # Cobra commands, API client, config file (0600) for the nook CLI
│   ├── version/               # build info set via ldflags
│   ├── testinfra/             # testcontainers helpers: Postgres, Redis, Dex (integration build tag only)
│   ├── queue/                 # (planned) Redis-backed job queue
│   ├── scheduler/             # (planned) placement + failover
│   ├── agent/                 # worker agent: state dir, join, mTLS stream, heartbeats, Docker client, renewal, local health
│   └── gateway/               # (planned) gateway logic
├── migrations/                # goose SQL migrations, embedded into the binary by migrations.go
├── tools/
│   └── devenv/                # `make env`: creates/updates .env with generated secrets and bcrypt hashes (dev only)
├── proto/                     # protobuf/gRPC definitions (nook/agent/v1) + committed generated Go code
├── frontend/                  # (planned) React dashboard
├── deploy/
│   ├── compose/docker-compose.dev.yml   # Postgres, Redis, MinIO, Dex for development
│   ├── compose/dex/config.yaml          # Dex dev/test IdP config (static users; shared with integration tests)
│   ├── docker/nook-server.Dockerfile    # multi-stage, distroless, non-root
│   └── docker/nook-agent.Dockerfile     # multi-arch, distroless, non-root; Docker socket = root on the host (dedicated workers only)
├── test/e2e/                  # (planned) end-to-end tests
└── docs/
    ├── architecture.md        # the full system map
    ├── decisions/             # ADRs 0001-*.md ...
    └── learn/                 # plain-English stage notes
```
