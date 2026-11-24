# syntax=docker/dockerfile:1
#
# nook-agent image, built for linux/amd64 and linux/arm64:
#   make docker-build
#
# SECURITY: the agent controls the node's Docker engine through its socket.
# Access to that socket is equivalent to root on the machine (anyone who can
# start containers can mount the host's file system), so the agent, in or
# out of a container, belongs only on dedicated worker machines. The image
# runs as an unprivileged user anyway, which limits what a compromised agent
# can do to the container itself (its state directory) without the socket.
#
# Run it with the host's network (so it reports the machine's hostname and
# addresses), the Docker socket, the socket's group, Docker's data
# directory read-only (for disk statistics) and a volume for its identity:
#
#   docker run -d --name nook-agent --restart unless-stopped \
#     --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
#     --group-add "$(stat -c %g /var/run/docker.sock)" \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -v /var/lib/docker:/var/lib/docker:ro \
#     -v nook-agent:/var/lib/nook-agent \
#     nook-agent:<version> run
#
# Join first with the same mounts and
#   ... nook-agent:<version> join --server ... --token ... --ca-hash ...

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

WORKDIR /src

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

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/the-asmit/nook/internal/version.Version=${VERSION} \
        -X github.com/the-asmit/nook/internal/version.Commit=${COMMIT} \
        -X github.com/the-asmit/nook/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/nook-agent ./cmd/nook-agent \
 && mkdir -p /out/state

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="nook-agent" \
      org.opencontainers.image.description="Nook worker-node agent" \
      org.opencontainers.image.source="https://github.com/the-asmit/nook" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=build /out/nook-agent /nook-agent
# The state directory holds the node's private key: owned by the agent's
# user and closed to everyone else (the agent refuses looser modes).
COPY --from=build --chown=65532:65532 --chmod=0700 /out/state /var/lib/nook-agent

USER 65532:65532
VOLUME ["/var/lib/nook-agent"]
ENTRYPOINT ["/nook-agent"]
CMD ["run"]
