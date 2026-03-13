# Build stage — builds both queue-manager and mail-remote binaries.
# mail-remote is invoked as a subprocess by queue-manager for each delivery.
#
# For CI builds, mail-remote is cloned using GITHUB_TOKEN (build secret).
# For local builds, pre-clone mail-remote into .mail-remote/ in this directory.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git

# Build mail-remote first (separate module).
# Try local copy first (.mail-remote/), fall back to git clone with token.
WORKDIR /mail-remote
COPY .mail-remote* /tmp/mail-remote-local/
RUN --mount=type=secret,id=github_token \
    if [ -f /tmp/mail-remote-local/go.mod ]; then \
        cp -a /tmp/mail-remote-local/. .; \
    else \
        TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
        if [ -n "$TOKEN" ]; then \
            git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"; \
        fi; \
        git clone --depth 1 https://github.com/infodancer/maildancer/internal/mail-remote.git .; \
        git config --global --unset-all url.https://x-access-token 2>/dev/null || true; \
    fi
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mail-remote ./cmd/mail-remote

# Build queue-manager
WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=secret,id=github_token \
    TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    if [ -n "$TOKEN" ]; then \
        GONOSUMCHECK=github.com/infodancer/* \
        GOFLAGS=-insecure \
        GOPRIVATE=github.com/infodancer/* \
        git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"; \
    fi; \
    GOPRIVATE=github.com/infodancer/* go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o queue-manager ./cmd/queue-manager

# Runtime stage
FROM scratch
COPY --from=builder /build/queue-manager /queue-manager
COPY --from=builder /bin/mail-remote /mail-remote
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/queue-manager"]
CMD ["--config", "/etc/infodancer/config.toml", "--queue", "/var/spool/mail-queue", "--binary", "/mail-remote"]
