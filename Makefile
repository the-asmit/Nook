# Nook developer tasks. Run `make help` to list them.
#
# Every target runs inside WSL2/Linux (or macOS) with Go, Docker and gcc
# (needed by the race detector) installed; see README.md.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-print-directory

MODULE := github.com/the-asmit/nook
BIN_DIR := $(CURDIR)/bin

# Build metadata, computed once per make invocation (the second assignment
# turns the lazily evaluated ?= value into a fixed one).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION := $(VERSION)
COMMIT ?= $(shell git rev-parse --verify --quiet HEAD 2>/dev/null || echo unknown)
COMMIT := $(COMMIT)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_DATE := $(BUILD_DATE)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

# Pinned tool versions. Tools are installed into bin/ with the version in
# the file name, so bumping a version here reinstalls it automatically.
GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION := v1.10.0
SQLC_VERSION := v1.31.1
GORELEASER_VERSION := v2.20.2
BUF_VERSION := v1.75.0
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2
# The goose CLI and protoc-gen-go always match their library versions in
# go.mod, so generated code and runtime never disagree.
GOOSE_VERSION := $(shell go list -m -f '{{.Version}}' github.com/pressly/goose/v3)
PROTOC_GEN_GO_VERSION := $(shell go list -m -f '{{.Version}}' google.golang.org/protobuf)

GOLANGCI_LINT := $(BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)
GOVULNCHECK := $(BIN_DIR)/govulncheck-$(GOVULNCHECK_VERSION)
GOOSE := $(BIN_DIR)/goose-$(GOOSE_VERSION)
SQLC := $(BIN_DIR)/sqlc-$(SQLC_VERSION)
GORELEASER := $(BIN_DIR)/goreleaser-$(GORELEASER_VERSION)
BUF := $(BIN_DIR)/buf-$(BUF_VERSION)
# buf runs the code generators from PATH; this directory holds exactly the
# pinned versions.
PROTOC_PLUGINS := $(BIN_DIR)/protoc-plugins-$(PROTOC_GEN_GO_VERSION)-$(PROTOC_GEN_GO_GRPC_VERSION)

# buf breaking compares proto/ against this git ref (CI uses origin/main).
BREAKING_REF ?= main

REDOCLY_IMAGE := redocly/cli:2.76.0@sha256:bd2a1637e39de2d7fc403b3a114b6f8ecbb7edcb6f814516c79b38be409747e9

COMPOSE := docker compose --env-file .env -f deploy/compose/docker-compose.dev.yml

IMAGE ?= nook-server
AGENT_IMAGE ?= nook-agent
GATEWAY_IMAGE ?= nook-gateway
POSTGRES_IMAGE ?= nook-postgres
PLATFORMS ?= linux/amd64,linux/arm64
# --load imports the multi-platform image into the local image store (needs
# Docker's containerd image store, the default in Docker Desktop). CI sets
# DOCKER_OUTPUT= to build without exporting anything.
DOCKER_OUTPUT ?= --load
DOCKER_RUN_PORT ?= 8081

##@ General

.PHONY: help
help: ## List available targets
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} \
		/^[a-zA-Z0-9_.-]+:.*## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

##@ Development stack

.PHONY: env
env: ## Create .env from .env.example, or add variables it gained (keeps existing values)
	@go run ./tools/devenv

.PHONY: dev-up
dev-up: env ## Start Postgres, Redis, MinIO, the registry and Dex and wait until healthy
	@# The registry's TLS certificate comes from Nook's CA (created here if
	@# the server has not run yet); kept while it stays valid.
	set -a; source ./.env; set +a; \
		go run ./cmd/nook-server registry-cert --out .nook-dev/registry --names registry,localhost,127.0.0.1
	@# The master key for app environment variables; never overwritten.
	@test -f .nook-dev/secrets.key || go run ./cmd/nook-server secrets init --out .nook-dev/secrets.key
	$(COMPOSE) up --detach --wait --wait-timeout 180
	@# Docker Desktop can silently skip publishing a port that another program
	@# (say a native Windows PostgreSQL) already holds; 127.0.0.1:<port> would
	@# then reach that program instead of the container. Fail loudly instead.
	@for sp in postgres:5432 redis:6379 minio:9000 minio:9001 registry:5000 dex:5556; do \
		bound=$$($(COMPOSE) port "$${sp%%:*}" "$${sp##*:}" 2>/dev/null || true); \
		if [[ ! "$$bound" =~ ^127\.0\.0\.1:[1-9][0-9]*$$ ]]; then \
			echo "error: $$sp is not published on the host (another program holds the port?)." >&2; \
			echo "       Choose a free port with the matching *_PORT variable in .env, then run 'make dev-down dev-up'." >&2; \
			exit 1; \
		fi; \
		echo "$$sp -> $$bound"; \
	done

.PHONY: dev-down
dev-down: env ## Stop the development stack (data volumes are kept)
	$(COMPOSE) down

.PHONY: dev-logs
dev-logs: env ## Follow the development stack's logs
	$(COMPOSE) logs --follow --tail=100

.PHONY: run-gateway
run-gateway: build env ## Run nook-gateway against the dev control plane (apps at http://<app>--<ws>.apps.localhost:<GATEWAY_PORT>)
	set -a; source ./.env; set +a; exec $(BIN_DIR)/nook-gateway

.PHONY: run-agent
run-agent: build env ## Run nook-agent for this machine against the dev stack (join it first; see README)
	set -a; source ./.env; set +a; exec $(BIN_DIR)/nook-agent run

.PHONY: run-server
run-server: build env ## Build and run nook-server against the dev stack
	set -a; source ./.env; set +a; exec $(BIN_DIR)/nook-server

.PHONY: docker-run
docker-run: env ## Run the server, agent and gateway images (make docker-build) against the dev stack; stop with make docker-stop
	@# Settings come from .env, rewritten per container into env files under
	@# .nook-dev/docker/; see deploy/docker/dev-run.sh for the layout and limits.
	IMAGE=$(IMAGE) AGENT_IMAGE=$(AGENT_IMAGE) GATEWAY_IMAGE=$(GATEWAY_IMAGE) VERSION=$(VERSION) \
		DOCKER_RUN_PORT=$(DOCKER_RUN_PORT) deploy/docker/dev-run.sh up

.PHONY: docker-stop
docker-stop: ## Remove the containers make docker-run started
	IMAGE=$(IMAGE) AGENT_IMAGE=$(AGENT_IMAGE) GATEWAY_IMAGE=$(GATEWAY_IMAGE) VERSION=$(VERSION) \
		DOCKER_RUN_PORT=$(DOCKER_RUN_PORT) deploy/docker/dev-run.sh down

.PHONY: migrate-new
migrate-new: $(GOOSE) ## Create a new SQL migration: make migrate-new name=add_users
	@[[ "$(name)" =~ ^[a-z][a-z0-9_]*$$ ]] || { echo "usage: make migrate-new name=<lower_snake_case_description>" >&2; exit 2; }
	$(GOOSE) -dir migrations -s create "$(name)" sql

##@ Build and test

.PHONY: build
build: ## Build bin/nook-server, bin/nook (the CLI) and bin/nook-agent for this machine
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/nook-server ./cmd/nook-server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/nook ./cmd/nook
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/nook-agent ./cmd/nook-agent
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/nook-gateway ./cmd/nook-gateway

.PHONY: proto
proto: $(BUF) $(PROTOC_PLUGINS) ## Regenerate the gRPC/protobuf Go code in proto/ (committed)
	PATH="$(PROTOC_PLUGINS):$$PATH" $(BUF) generate

.PHONY: proto-check
proto-check: $(BUF) $(PROTOC_PLUGINS) ## Fail if the generated protobuf code is stale (used by CI)
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	PATH="$(PROTOC_PLUGINS):$$PATH" $(BUF) generate --output "$$tmp"; \
	diff -r --exclude='*.proto' "$$tmp/proto" proto || { echo "error: proto/ is stale; run 'make proto' and commit the result." >&2; exit 1; }; \
	echo "generated protobuf code is up to date"

.PHONY: proto-lint
proto-lint: $(BUF) ## Lint the protobuf definitions (buf lint)
	$(BUF) lint

.PHONY: proto-breaking
proto-breaking: $(BUF) ## Fail on breaking protobuf changes against BREAKING_REF (default main)
	@# Until the base has a buf module there is nothing to compare against.
	@if git cat-file -e "$(BREAKING_REF):buf.yaml" 2>/dev/null; then \
		$(BUF) breaking --against ".git#ref=$(BREAKING_REF)"; \
		echo "no breaking changes against $(BREAKING_REF)"; \
	else \
		echo "$(BREAKING_REF) has no protobuf module yet; nothing to compare against."; \
	fi

.PHONY: sqlc
sqlc: $(SQLC) ## Regenerate internal/store from migrations/ and internal/store/queries/
	cd internal/store && $(SQLC) generate

.PHONY: sqlc-check
sqlc-check: $(SQLC) ## Fail if the generated sqlc code is stale (used by CI)
	cd internal/store && $(SQLC) diff

.PHONY: openapi-lint
openapi-lint: ## Validate api/openapi.yaml against OpenAPI 3.1 (Redocly CLI in Docker)
	docker run --rm -v "$(CURDIR)/api:/spec:ro" -w /spec $(REDOCLY_IMAGE) lint --config=/spec/redocly.yaml openapi.yaml

.PHONY: release-snapshot
release-snapshot: $(GORELEASER) ## Build CLI archives for every OS/arch into dist/ without publishing
	$(GORELEASER) release --snapshot --clean --skip=publish

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -shuffle=on -count=1 ./...

.PHONY: test-integration
test-integration: ## Run unit + integration tests (needs Docker, no internet) with the race detector
	go test -race -shuffle=on -count=1 -tags=integration -timeout=40m ./...

.PHONY: test-e2e-internet
test-e2e-internet: ## Run the end-to-end tests that need the public internet (Docker Hub, public DNS)
	@# Files tagged `integration && internet`, tests named TestE2E*; CI runs
	@# them on a schedule and before releases (.github/workflows/e2e-internet.yml).
	go test -race -count=1 -tags=integration,internet -timeout=40m -run '^TestE2E' ./...

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint (including integration-tagged files)
	$(GOLANGCI_LINT) run ./...

.PHONY: fmt
fmt: $(GOLANGCI_LINT) ## Format code (gofmt + goimports) and tidy go.mod
	$(GOLANGCI_LINT) fmt ./...
	go mod tidy

.PHONY: vuln
vuln: $(GOVULNCHECK) ## Scan production code, then test code, for known vulnerabilities
	$(GOVULNCHECK) ./...
	$(GOVULNCHECK) -test -tags=integration ./...

.PHONY: docker-build
docker-build: ## Build the nook-server, nook-agent, nook-gateway and nook-postgres images for linux/amd64 and linux/arm64
	docker buildx build \
		--platform $(PLATFORMS) \
		--file deploy/docker/nook-server.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(IMAGE):$(VERSION) \
		$(DOCKER_OUTPUT) .
	docker buildx build \
		--platform $(PLATFORMS) \
		--file deploy/docker/nook-agent.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(AGENT_IMAGE):$(VERSION) \
		$(DOCKER_OUTPUT) .
	docker buildx build \
		--platform $(PLATFORMS) \
		--file deploy/docker/nook-gateway.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(GATEWAY_IMAGE):$(VERSION) \
		$(DOCKER_OUTPUT) .
	docker buildx build \
		--platform $(PLATFORMS) \
		--file deploy/docker/nook-postgres.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(POSTGRES_IMAGE):$(VERSION) \
		$(DOCKER_OUTPUT) .

.PHONY: docker-postgres
docker-postgres: ## Build nook-postgres:dev (the app database server) for this machine, for the dev stack
	docker buildx build --load \
		--file deploy/docker/nook-postgres.Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(POSTGRES_IMAGE):dev .

.PHONY: tools
tools: $(GOLANGCI_LINT) $(GOVULNCHECK) $(GOOSE) $(SQLC) $(GORELEASER) $(BUF) $(PROTOC_PLUGINS) ## Install the pinned developer tools into bin/

.PHONY: clean
clean: ## Remove build output, release archives and installed tools
	rm -rf $(BIN_DIR) dist

# Tool installation. go install builds each tool with the local Go
# toolchain, which guarantees it understands this module's Go version.
$(GOLANGCI_LINT):
	@mkdir -p $(BIN_DIR)/.install
	GOBIN=$(BIN_DIR)/.install go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv $(BIN_DIR)/.install/golangci-lint $@

$(GOVULNCHECK):
	@mkdir -p $(BIN_DIR)/.install
	GOBIN=$(BIN_DIR)/.install go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	mv $(BIN_DIR)/.install/govulncheck $@

# Only the Postgres driver is compiled in; the others are not needed.
$(GOOSE):
	@mkdir -p $(BIN_DIR)/.install
	GOBIN=$(BIN_DIR)/.install go install \
		-tags='no_clickhouse no_libsql no_mssql no_mysql no_sqlite3 no_vertica no_ydb' \
		github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)
	mv $(BIN_DIR)/.install/goose $@

# sqlc embeds the PostgreSQL parser, which needs cgo (gcc) to build.
$(SQLC):
	@mkdir -p $(BIN_DIR)/.install
	GOBIN=$(BIN_DIR)/.install go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)
	mv $(BIN_DIR)/.install/sqlc $@

$(GORELEASER):
	@mkdir -p $(BIN_DIR)/.install
	GOBIN=$(BIN_DIR)/.install go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)
	mv $(BIN_DIR)/.install/goreleaser $@

$(BUF):
	@mkdir -p $(BIN_DIR)/.install
	GOBIN=$(BIN_DIR)/.install go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	mv $(BIN_DIR)/.install/buf $@

$(PROTOC_PLUGINS):
	@mkdir -p $(BIN_DIR)/.install-plugins
	GOBIN=$(BIN_DIR)/.install-plugins go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(BIN_DIR)/.install-plugins go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	mv $(BIN_DIR)/.install-plugins $@
