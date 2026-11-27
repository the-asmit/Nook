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
   tag; they must not need the public internet (base images come from the
   test registry). Tests that do (Docker Hub, public DNS) carry
   `//go:build integration && internet`, are named `TestE2E*` and run with
   `make test-e2e-internet`. `go test -race` must pass. No sleep-based timing in tests; poll with
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
    - Never add AI attribution (Co-Authored-By trailers or 'Generated with'
      lines) to commits or pull requests.
    - docs/ is local-only and is never committed.
    - Every stage is built on a branch feat/stage-N-<name> created from main
      and is not merged until the owner approves.

## Commands

All commands run inside WSL2 (Ubuntu) or Linux/macOS. `make help` lists all.

| Task | Command |
|------|---------|
| Create/update `.env` | `make env` (adds new variables, never changes existing values) |
| Start Postgres/Redis/MinIO/registry/Dex | `make dev-up` (runs `make env`, issues the registry certificate) |
| Run the control plane | `make run-server` |
| Run a dev worker agent (after `nook-agent join --state-dir .nook-dev/agent`) | `make run-agent` |
| Run the dev gateway (apps at `http://<app>--<ws>.apps.localhost:8090`) | `make run-gateway` |
| Unit tests (race) | `make test` |
| Unit + integration tests | `make test-integration` (needs Docker, no internet) |
| End-to-end tests that need the internet | `make test-e2e-internet` (CI: nightly and on version tags) |
| Lint / format | `make lint` / `make fmt` |
| Vulnerability scan | `make vuln` |
| New migration | `make migrate-new name=add_users` |
| Regenerate store / check it | `make sqlc` / `make sqlc-check` |
| Regenerate protobuf / check it | `make proto` / `make proto-check` |
| Lint protobuf / breaking changes | `make proto-lint` / `make proto-breaking` (against `main`) |
| Validate the OpenAPI spec | `make openapi-lint` |
| CLI release archives | `make release-snapshot` (into `dist/`) |
| Multi-arch images (server, agent, gateway, postgres) | `make docker-build`, then `make docker-run` (server, agent and gateway against the dev stack) / `make docker-stop` |
| App database server image for this machine | `make docker-postgres` (nook-postgres:dev; integration tests build nook-postgres:it themselves) |
| Master key for app environment variables | `go run ./cmd/nook-server secrets init --out FILE` (`make dev-up` does it) |
| Show the agent's egress rules | `go run ./cmd/nook-agent firewall rules` |

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
- **Builds and images**: images are always referenced by digest
  (`<registry>/<workspace-id>/<app-id>@sha256:...`); tags are per build
  (`b-<build-id>`) and never trusted. Each app's BuildKit cache lives in
  `<workspace-id>/<app-id>/cache:buildcache`, reachable only with that
  app's build token; purges and stray cleanup cover it. Deployment and build state changes
  are compare-and-set updates in Postgres; the Redis Streams queue only
  carries hints (jobs are idempotent by deployment ID). Singleton cleanup
  belongs to `builds.Janitor` (leader only, idempotent tasks).
- **Credentials we hand out** (presigned storage URLs, registry tokens)
  are never logged or put into errors; strip `*url.Error` before wrapping.
  Registry tokens are scoped to one repository and expire.
- **Untrusted code**: Dockerfiles and source archives are hostile input.
  Extract only through `archive.Extract`; run builds only in the locked-down
  container `internal/agent` creates.
- **Running apps**: releases go through `rollout` (never start containers
  any other way); deployment and instance state changes are
  compare-and-set updates. A deployment is image + environment snapshot;
  environment changes and rollbacks create new deployments (`config`,
  `rollback`). Placement happens only in `scheduler.Place` inside a
  transaction that locks the workspace row, then node rows (in that
  order). Agents restart crashed containers themselves (no Docker
  restart policy).
- **Environment values** are sealed with `secrets.Keyring` bound to app
  and key (`secrets.EnvAAD`); plaintext exists only in the
  `StartInstance` command. Never log, audit, return or put in errors a
  value; secret values are never returned by the API at all. Members set
  plain variables; secrets need admins or owners.
- **App containers** keep the hardening in `appContainerSpec`: all
  capabilities dropped, no-new-privileges, limits, no host mounts or
  Docker socket, own network, port published only on the advertise
  address. Container egress is filtered by the agent's firewall (DNS only
  to the resolvers it reads from the node, port 53 only); any new
  container kind joins a filtered bridge.
- **The gateway** holds no database credentials or OIDC secret: it uses
  the control plane's `/internal/v1` API (shared `NOOK_GATEWAY_SECRET`,
  404 otherwise). Anything that can change a route (instance health,
  switch-over, stop/start, delete, access changes) calls
  `RouteEvents.Changed`; the hint is best-effort, the gateway's resync is
  the safety net. App hosts are `<app>--<workspace>.<apps domain>`, so
  slugs never contain `--` and the label stays within 63 characters.
- **Visitor sessions** never span hosts: each app host gets its own
  host-only (`__Host-` over HTTPS) cookie via a single-use, host-bound,
  one-minute code from the auth host. Everything a session or code
  authorizes is checked together with the host. `/_nook/*` on app hosts
  belongs to the gateway; incoming `X-Nook-*` headers and Nook cookies
  are always stripped before proxying. Return paths go through
  `auth.SafeReturnPath`; redirect targets never come from request hosts.
- **Gateway → app** traffic is plain HTTP on the private network, guarded
  by the agent firewall (`NOOK_AGENT_GATEWAY_ADDRS`) and by the agent
  refusing a public advertise/publish address without
  `NOOK_AGENT_ALLOW_PUBLIC_ADVERTISE_ADDR`; this is the one documented
  exception to TLS outside localhost (ADR 0028). Keep both guards.
- **Sleep and wake**: apps are stateless in v1 (they may stop, move or
  briefly run twice). Sleeping releases the reservation and keeps the
  stopped container (`keep_container`); a wake is the compare-and-set
  `WakeApp`, never a direct start, and resumes on the previous node when
  it fits (`scheduler.Place` with `Resume`). Gateways record activity only
  through `activity.Recorder` and hold requests only through the waker
  (singleflight, bounded, timeout → 503 + `Retry-After`). Eviction happens
  only inside `scheduler.Place`'s transaction and is audited
  (`app.evict`); never evict `sleep_after = never` apps.
- **Failover and draining** are the leader's relocation pass (on the lock
  connection; agent commands and events run afterwards as `FollowUps`).
  Replacements always go through the owner's converge and the normal
  rollout path; draining is make-before-break. What serves is decided only
  by `app_instances` rows (fencing): never route to or trust an instance
  because its container runs. Record why an instance exists in
  `cause`/`cause_at` and why it stopped in `stop_reason`.
- **App databases**: one server per installation, managed only by
  `appdb` (the leader's pass decides on the lock connection; agent
  commands and SQL on the server run afterwards). App code never shares
  Nook's own Postgres. One database and role per app, named
  `DatabaseName(app id)`, `CONNECT` revoked from `PUBLIC`; roles get
  SCRAM verifiers, never plaintext passwords; passwords and the superuser
  password are sealed with the keyring (`DatabasePasswordAAD`,
  `DatabaseSuperuserAAD`) and never logged, audited or returned.
  `DATABASE_URL` is set only through `apps.SetManagedEnv` (users cannot
  change it). DDL identifiers go through `sqlIdent`/`sqlLiteral`. Backups
  are encrypted with the key derived from the recorded master key version
  (`backup_key_version`); keep that version in the keyring. Every server
  state change is a compare-and-set; apps may reach only the current
  endpoint (agent firewall), and a replaced server is stopped, never
  reused (its volume stays until an admin removes it).
- **Spelling**: code and prose use US English (`canceled`); the API and
  database status value is `cancelled`, as specified.
- **Tests** never sleep to wait; they poll with a deadline or synchronize on
  channels. Integration tests in `internal/server` share one Postgres,
  Redis and Dex (`harness_integration_test.go`) and get a fresh database per
  test; the OIDC flow is always exercised against the real Dex. App
  database tests build `nook-postgres:it` from its Dockerfile once per run
  (Docker caches it) and keep backups under a prefix of their own. Every
  agent's firewall filters all app bridges of its machine, so stop a dev
  agent and run `nook-agent firewall remove` before the integration suite.

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
│   ├── nook-server/           # control plane entry point (+ `registry-cert`, `secrets init|add-key|rotate-key`)
│   ├── nook/                  # CLI entry point
│   ├── nook-agent/            # worker agent entry point: `join`, `run`, `firewall rules|remove`, `version`
│   └── nook-gateway/          # gateway entry point (the only public entry point)
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
│   │   ├── testdata/testapp/  # tiny app the runtime integration tests release (built and pushed by the tests)
│   │   ├── api/               # Gin router, ops endpoints, /api/v1 JSON handlers, /internal/v1 for gateways
│   │   └── web/               # server-rendered pages: sign-in, sign-out, not-invited, device approval, auth host (/_visitor)
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
│   ├── objstore/              # S3-compatible storage (SigV4): presigned upload/download URLs, verified HEAD, small objects
│   ├── registry/              # private registry: repository-scoped ES256 tokens (x5c chain to the CA) + registry API client
│   ├── archive/               # reproducible source archives (ignore files) and hostile-archive-safe extraction (os.Root)
│   ├── apps/                  # apps, quotas, deployments, verified uploads, settings, stop/start, rollback, encrypted env, access policies (tenant-scoped)
│   ├── builds/                # deployment queue (Redis Streams), dispatcher, agent results, live logs, janitor, registry GC windows
│   ├── rollout/               # releases: placement → StartInstance → health-gated switch → drain; desired state, reconciliation, app log streams,
│   │                          #   sleeping idle apps, waking (one per app), failover of dead nodes' instances, draining (leader passes)
│   ├── secrets/               # AES-256-GCM keyring (versioned master key), key checks, rotation
│   ├── cli/                   # Cobra commands, API client, config file (0600) for the nook CLI
│   ├── version/               # build info set via ldflags
│   ├── testinfra/             # testcontainers helpers: Postgres, Redis, Dex, MinIO, registry (integration build tag only)
│   ├── scheduler/             # best-fit placement on reserved memory/CPU, serialized by node row locks; LRU eviction of idle apps on one node
│   ├── agent/                 # worker agent: state dir, join, mTLS stream, heartbeats, Docker client, renewal, local health,
│   │                          #   builds in locked-down rootless BuildKit containers (custom seccomp, userns check),
│   │                          #   app instances (pull by digest, hardened containers, health checks, crash backoff,
│   │                          #   adoption), log streaming, egress firewall (iptables via a helper container),
│   │                          #   the app database server container (start/restore, clean stop + final archive, backups, dumps)
│   ├── appdb/                 # app databases: the per-installation PostgreSQL server (placement, generations, failover by restore,
│   │                          #   fencing), per-app databases and roles, WAL-G backups, monitoring, dumps (leader pass + API side)
│   ├── activity/              # apps' last request times: gateways' batched writes to a Redis sorted set (ZADD GT), reads for sleep and eviction
│   ├── routes/                # app host scheme (<app>--<ws>.<domain>), route records, nook:routes Pub/Sub events
│   ├── visitor/               # visitor sign-in: auth-host sessions, single-use host-bound codes, access checks, sealed certificates
│   └── gateway/               # nook-gateway: route table, reverse proxy, visitor sessions, TLS modes, rate limits, pages, drain
├── migrations/                # goose SQL migrations, embedded into the binary by migrations.go
├── tools/
│   └── devenv/                # `make env`: creates/updates .env with generated secrets and bcrypt hashes (dev only)
├── proto/                     # protobuf/gRPC definitions (nook/agent/v1) + committed generated Go code
├── frontend/                  # (planned) React dashboard
├── deploy/
│   ├── compose/docker-compose.dev.yml   # Postgres, Redis, MinIO, Dex for development
│   ├── compose/dex/config.yaml          # Dex dev/test IdP config (static users; shared with integration tests)
│   ├── compose/registry/config.yml      # CNCF Distribution config (S3 storage, TLS, token auth; shared with integration tests)
│   ├── compose/registry/gc.sh           # registry blob GC inside a control-plane maintenance window
│   ├── docker/nook-server.Dockerfile    # multi-stage, distroless, non-root
│   ├── docker/nook-agent.Dockerfile     # multi-arch, distroless, non-root; Docker socket = root on the host (dedicated workers only)
│   ├── docker/nook-gateway.Dockerfile   # multi-arch, distroless, non-root; stateless
│   ├── docker/nook-postgres.Dockerfile  # app database server: PostgreSQL + checksum-pinned WAL-G, multi-arch, no RUN steps
│   └── docker/nook-db.sh                # nook-postgres entrypoint: init/restore/run, backup, final-archive, tls, dump
├── examples/                  # hello-go and hello-node: tiny apps with Dockerfile + nook.toml (used by tests and the README);
│                              #   notes-go: a notes app on an app database (its own module)
├── test/e2e/                  # (planned) end-to-end tests
└── docs/
    ├── architecture.md        # the full system map
    ├── decisions/             # ADRs 0001-*.md ...
    └── learn/                 # plain-English stage notes
```
