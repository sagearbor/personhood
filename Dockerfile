# Personhood server — multi-stage Dockerfile.
#
# Stage 1 (builder): pulls the Go workspace, compiles the server binary with
# build tags `sendgrid twilio` so real vendor senders are linked in.
#
# Stage 2 (runtime): distroless base-debian12 (glibc, for the Barretenberg
# CLI that document-chip-zk verifies proofs with), runs as non-root, carries
# the binary, bb, CA roots and any built circuit artifacts. No shell —
# exec-form CMD only.

ARG GO_VERSION=1.22.7

# -----------------------------------------------------------------------------
# Builder
# -----------------------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src

# Build the server as a standalone module (GOWORK=off): src/server/go.mod
# carries a `replace` for every sibling module it needs, so the image build
# does not depend on go.work at all. go.work is a developer-workspace
# convenience that also lists test/tool modules the binary never needs — a
# previous version of this file broke every time a module was added there.
# The .dockerignore keeps host artifacts (node_modules, .next, docs, app/)
# out of the build context.
ENV GOWORK=off
COPY pkg     pkg
COPY src     src
COPY sdk     sdk

# No BuildKit cache mounts here: Cloud Run source deploys build this file
# with Cloud Build's legacy (non-BuildKit) docker builder, which rejects
# `--mount=type=cache`. Local `docker build` is a little slower without the
# mounts, but every builder can run this file.
RUN cd src/server && go mod download

# Compile with sendgrid + twilio so real senders are linked. CGO disabled so
# we get a fully static binary that distroless can run. TARGETARCH is filled
# in by BuildKit (docker compose, buildx), so the issuer kit builds natively
# on arm64 boxes too; Cloud Build's legacy builder leaves it empty -> amd64.
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64}
RUN cd src/server && \
    go build -tags 'sendgrid twilio' -trimpath -ldflags="-s -w" \
      -o /out/personhood-server ./cmd/server

# Barretenberg CLI for document-chip-zk (docs/zk-passport.md): bb 5.0.0 from
# the npm package @aztec/bb.js 5.0.0 (MIT), checked against a pinned SHA-256
# of the package tarball. Only one ~38 MB file is kept. Used only when
# DOCUMENT_CHIP_ZK=1.
ARG BBJS_SHA256=e7153e43d900d67e2ce4c55498bded8f0957a988f83ea4fe99c269b877dcc677
RUN curl -sfL -o /tmp/bbjs.tgz https://registry.npmjs.org/@aztec/bb.js/-/bb.js-5.0.0.tgz && \
    echo "${BBJS_SHA256}  /tmp/bbjs.tgz" | sha256sum -c - && \
    tar -xzf /tmp/bbjs.tgz -C /tmp package/build/${GOARCH}-linux/bb && \
    install -m 0755 /tmp/package/build/${GOARCH}-linux/bb /out/bb && \
    rm -rf /tmp/bbjs.tgz /tmp/package

# Circuit artifacts + SRS for document-chip-zk, if tools/zk-circuits/build.sh
# was run before the image build (tools/zk-circuits/dist is not in git).
# Without them the image still runs; DOCUMENT_CHIP_ZK_ARTIFACTS_URL can point
# the wallet elsewhere.
COPY tools/zk-circuits /tmp/zk-circuits
RUN mkdir -p /out/zk-artifacts && \
    if [ -d /tmp/zk-circuits/dist ]; then cp /tmp/zk-circuits/dist/* /out/zk-artifacts/; fi && \
    rm -rf /tmp/zk-circuits

# -----------------------------------------------------------------------------
# Runtime
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder /out/personhood-server /usr/local/bin/personhood-server
COPY --from=builder /out/bb /usr/local/bin/bb
COPY --from=builder /out/zk-artifacts /zk-artifacts

# Run as the unprivileged user shipped in the distroless/nonroot image
# (uid 65532). Declared explicitly so static analysis can see we never
# fall back to root.
USER nonroot:nonroot

# Default to listening on 0.0.0.0:8080 inside the container; the host port
# is mapped by docker run / fly.toml.
ENV SERVER_ADDR=":8080"
EXPOSE 8080

# document-chip-zk stays off unless DOCUMENT_CHIP_ZK=1; these only say where
# its pieces are in this image.
ENV DOCUMENT_CHIP_ZK_BB=/usr/local/bin/bb \
    DOCUMENT_CHIP_ZK_ARTIFACTS_DIR=/zk-artifacts

# Required env at runtime:
#   ISSUER_ED25519_SK_B64   (issuer signing key)
#   SERVER_PUBLIC_URL       (full public URL, used for did:web + magic links)
# Optional:
#   CORS_ALLOWED_ORIGINS, SENDGRID_*, TWILIO_*, PERSONA_*
ENTRYPOINT ["/usr/local/bin/personhood-server"]
