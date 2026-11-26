# syntax=docker/dockerfile:1
#
# nook-gateway image, built for linux/amd64 and linux/arm64:
#   make docker-build
#
# The build stage always runs on the build machine's own architecture
# (--platform=$BUILDPLATFORM) and cross-compiles with GOOS/GOARCH, which is
# fast and needs no QEMU emulation. The final stage has no RUN steps, so it
# assembles for any target platform without emulation as well.

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

WORKDIR /src

# Dependencies first, so this layer is cached until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
COPY proto ./proto

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# CGO off gives a static binary that runs on distroless/static; -trimpath
# strips local paths for reproducible builds; -s -w drops debug symbols.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/the-asmit/nook/internal/version.Version=${VERSION} \
        -X github.com/the-asmit/nook/internal/version.Commit=${COMMIT} \
        -X github.com/the-asmit/nook/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/nook-gateway ./cmd/nook-gateway

# distroless/static: CA certificates, tzdata and /etc/passwd, but no shell
# or package manager, so there is almost nothing to exploit or patch.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="nook-gateway" \
      org.opencontainers.image.description="Nook gateway: the public entry point for apps" \
      org.opencontainers.image.source="https://github.com/the-asmit/nook" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/nook-gateway /nook-gateway

# The image's "nonroot" user (UID/GID 65532), stated numerically so
# Kubernetes' runAsNonRoot check can verify it without reading /etc/passwd.
USER 65532:65532
# 8080/8443: HTTP and HTTPS (set NOOK_GATEWAY_HTTP_ADDR=:8080 and
# NOOK_GATEWAY_HTTPS_ADDR=:8443; a non-root process cannot bind 80/443,
# map them with the container runtime). 9102: ops (health, metrics; set
# NOOK_GATEWAY_OPS_ADDR=:9102 and keep it off the public network).
# The gateway keeps no state on disk: routes come from the control plane,
# certificates are stored through it.
EXPOSE 8080 8443 9102
ENTRYPOINT ["/nook-gateway"]
