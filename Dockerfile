# syntax=docker/dockerfile:1.7
#
# Personhood server — multi-stage Dockerfile.
#
# Stage 1 (builder): pulls the Go workspace, compiles the server binary with
# build tags `sendgrid twilio` so real vendor senders are linked in.
#
# Stage 2 (runtime): distroless static-debian12, ~25 MB, runs as non-root,
# carries only the binary + CA roots. No shell — exec-form CMD only.

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

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    cd src/server && go mod download

# Compile with sendgrid + twilio so real senders are linked. CGO disabled so
# we get a fully static binary that distroless can run.
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    cd src/server && \
    go build -tags 'sendgrid twilio' -trimpath -ldflags="-s -w" \
      -o /out/personhood-server ./cmd/server

# -----------------------------------------------------------------------------
# Runtime
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/personhood-server /usr/local/bin/personhood-server

# Run as the unprivileged user shipped in the distroless/nonroot image
# (uid 65532). Declared explicitly so static analysis can see we never
# fall back to root.
USER nonroot:nonroot

# Default to listening on 0.0.0.0:8080 inside the container; the host port
# is mapped by docker run / fly.toml.
ENV SERVER_ADDR=":8080"
EXPOSE 8080

# Required env at runtime:
#   ISSUER_ED25519_SK_B64   (issuer signing key)
#   SERVER_PUBLIC_URL       (full public URL, used for did:web + magic links)
# Optional:
#   CORS_ALLOWED_ORIGINS, SENDGRID_*, TWILIO_*, PERSONA_*
ENTRYPOINT ["/usr/local/bin/personhood-server"]
