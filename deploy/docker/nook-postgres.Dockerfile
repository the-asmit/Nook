# syntax=docker/dockerfile:1
#
# nook-postgres: the app database server, built for linux/amd64 and
# linux/arm64 (make docker-build). PostgreSQL of the same major and patch
# release as the development stack, plus WAL-G for continuous archiving and
# base backups to S3-compatible storage. Agents run it; it is never started
# by hand. `nook-db` (deploy/docker/nook-db.sh) initializes, restores and
# runs the server and performs backups, dumps and the final archive.
#
# No RUN steps: WAL-G is downloaded and verified with ADD --checksum and the
# CA bundle is copied from a pinned image, so building arm64 on an amd64
# machine needs no emulation.

ARG WALG_VERSION=v3.0.10

# WAL-G release binaries (glibc, built on Ubuntu 24.04; the PostgreSQL
# image's Debian 13 has a newer glibc). The checksums are the release's
# published SHA-256 sums, checked again here on every build.
FROM scratch AS walg-amd64
ARG WALG_VERSION
ADD --checksum=sha256:481204eec9ca4418be345eea39da8dc6ff9cbcb16c7c259294b50477dc62f377 \
    https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}/wal-g-pg-24.04-amd64 /wal-g

FROM scratch AS walg-arm64
ARG WALG_VERSION
ADD --checksum=sha256:165c22724471127d2a08cbd3ff33503454f5252f5c5a8ab4aa0116895b880a40 \
    https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}/wal-g-pg-24.04-aarch64 /wal-g

FROM walg-${TARGETARCH} AS walg

# The PostgreSQL image has no CA bundle, without which WAL-G cannot verify
# a TLS object store (and the AWS SDK retries silently, which looks like a
# hang). Debian's bundle from the image the server already runs on.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS certs

FROM postgres:18.7-trixie@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a

ARG WALG_VERSION
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="nook-postgres" \
      org.opencontainers.image.description="Nook app database server: PostgreSQL with WAL-G" \
      org.opencontainers.image.source="https://github.com/the-asmit/nook" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      dev.nook.walg.version="${WALG_VERSION}"

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=walg --chmod=0755 /wal-g /usr/local/bin/wal-g
COPY --chmod=0755 deploy/docker/nook-db.sh /usr/local/bin/nook-db

# The data directory lives on the volume the agent mounts at
# /var/lib/postgresql; the server runs as the image's postgres user.
# PGUSER and PGHOST make psql, pg_isready and WAL-G use the control
# plane's role over the local socket.
ENV PGDATA=/var/lib/postgresql/18/nook \
    PGHOST=/var/run/postgresql \
    PGUSER=nook_admin \
    PGDATABASE=postgres \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER postgres
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/nook-db"]
CMD ["run"]
