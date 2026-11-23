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
# The goose CLI always matches the goose library version in go.mod.
GOOSE_VERSION := $(shell go list -m -f '{{.Version}}' github.com/pressly/goose/v3)

GOLANGCI_LINT := $(BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)
GOVULNCHECK := $(BIN_DIR)/govulncheck-$(GOVULNCHECK_VERSION)
GOOSE := $(BIN_DIR)/goose-$(GOOSE_VERSION)

COMPOSE := docker compose --env-file .env -f deploy/compose/docker-compose.dev.yml

IMAGE ?= nook-server
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

.env: ## Create .env from .env.example with freshly generated secrets
	@umask 077; awk ' \
		function secret(   cmd, s) { cmd = "od -An -N16 -tx1 /dev/urandom"; cmd | getline s; close(cmd); gsub(/[ \t]/, "", s); return s } \
		{ while (index($$0, "__GENERATED_SECRET__")) sub(/__GENERATED_SECRET__/, secret()); print }' \
		.env.example > $@
	@echo "Created .env with random development passwords."

.PHONY: dev-up
dev-up: .env ## Start Postgres, Redis and MinIO and wait until healthy
	$(COMPOSE) up --detach --wait --wait-timeout 180
	@# Docker Desktop can silently skip publishing a port that another program
	@# (say a native Windows PostgreSQL) already holds; 127.0.0.1:<port> would
	@# then reach that program instead of the container. Fail loudly instead.
	@for sp in postgres:5432 redis:6379 minio:9000 minio:9001; do \
		bound=$$($(COMPOSE) port "$${sp%%:*}" "$${sp##*:}" 2>/dev/null || true); \
		if [[ ! "$$bound" =~ ^127\.0\.0\.1:[1-9][0-9]*$$ ]]; then \
			echo "error: $$sp is not published on the host (another program holds the port?)." >&2; \
			echo "       Choose a free port with the matching *_PORT variable in .env, then run 'make dev-down dev-up'." >&2; \
			exit 1; \
		fi; \
		echo "$$sp -> $$bound"; \
	done

.PHONY: dev-down
dev-down: .env ## Stop the development stack (data volumes are kept)
	$(COMPOSE) down

.PHONY: dev-logs
dev-logs: .env ## Follow the development stack's logs
	$(COMPOSE) logs --follow --tail=100

.PHONY: run-server
run-server: build .env ## Build and run nook-server against the dev stack
	set -a; source ./.env; set +a; exec $(BIN_DIR)/nook-server

.PHONY: docker-run
docker-run: .env ## Run the nook-server image against the dev stack on 127.0.0.1:$(DOCKER_RUN_PORT)
	set -a; source ./.env; set +a; \
	export NOOK_HTTP_ADDR=":8080" \
		NOOK_POSTGRES_URL="postgres://$${POSTGRES_USER}:$${POSTGRES_PASSWORD}@postgres:5432/$${POSTGRES_DB}?sslmode=disable" \
		NOOK_REDIS_URL="redis://:$${REDIS_PASSWORD}@redis:6379/0"; \
	exec docker run --rm --name nook-server --network nook-dev \
		--publish 127.0.0.1:$(DOCKER_RUN_PORT):8080 \
		--read-only --cap-drop=ALL --security-opt=no-new-privileges \
		--env NOOK_ENV --env NOOK_LOG_LEVEL --env NOOK_HTTP_ADDR --env NOOK_POSTGRES_URL --env NOOK_REDIS_URL \
		$(IMAGE):$(VERSION)

.PHONY: migrate-new
migrate-new: $(GOOSE) ## Create a new SQL migration: make migrate-new name=add_users
	@[[ "$(name)" =~ ^[a-z][a-z0-9_]*$$ ]] || { echo "usage: make migrate-new name=<lower_snake_case_description>" >&2; exit 2; }
	$(GOOSE) -dir migrations -s create "$(name)" sql

##@ Build and test

.PHONY: build
build: ## Build bin/nook-server for this machine
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/nook-server ./cmd/nook-server

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -shuffle=on -count=1 ./...

.PHONY: test-integration
test-integration: ## Run unit + integration tests (needs Docker) with the race detector
	go test -race -shuffle=on -count=1 -tags=integration -timeout=20m ./...

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
docker-build: ## Build the nook-server image for linux/amd64 and linux/arm64
	docker buildx build \
		--platform $(PLATFORMS) \
		--file deploy/docker/nook-server.Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--tag $(IMAGE):$(VERSION) \
		$(DOCKER_OUTPUT) .

.PHONY: tools
tools: $(GOLANGCI_LINT) $(GOVULNCHECK) $(GOOSE) ## Install the pinned developer tools into bin/

.PHONY: clean
clean: ## Remove build output and installed tools
	rm -rf $(BIN_DIR)

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
