# syntax=docker/dockerfile:1
#
# queue-manager image. Builds the queue-manager scheduler together with the
# mail-remote delivery helper it invokes as a subprocess for each message.
# Both binaries live in this module, so -- unlike the pre-monorepo build that
# cloned mail-remote from a separate repo -- they build straight from the
# local tree. Build context is the repository root.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
# infodancer/logging is an external module; supply a token for the (possibly
# private) fetch if one is mounted, otherwise fall back to anonymous.
RUN --mount=type=secret,id=github_token \
    TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    if [ -n "$TOKEN" ]; then \
        git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"; \
    fi; \
    GOPRIVATE=github.com/infodancer/* go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/queue-manager ./cmd/queue-manager && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/mail-remote ./cmd/mail-remote

FROM scratch
COPY --from=builder /out/queue-manager /queue-manager
COPY --from=builder /out/mail-remote /mail-remote
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/queue-manager"]
CMD ["--config", "/etc/infodancer/config.toml", "--queue", "/var/spool/mail-queue", "--binary", "/mail-remote"]
