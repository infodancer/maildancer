# Build stage — builds both queue-manager and mail-remote binaries.
# mail-remote is invoked as a subprocess by queue-manager for each delivery.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git

# Build mail-remote first (separate private module)
WORKDIR /mail-remote
RUN --mount=type=secret,id=github_token \
    git config --global url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" && \
    git clone --depth 1 https://github.com/infodancer/maildancer/internal/mail-remote.git . && \
    git config --global --remove-section url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/"
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mail-remote ./cmd/mail-remote

# Build queue-manager
WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=secret,id=github_token \
    git config --global url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" && \
    go mod download && \
    git config --global --remove-section url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/"
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o queue-manager ./cmd/queue-manager

# Runtime stage
FROM scratch
COPY --from=builder /build/queue-manager /queue-manager
COPY --from=builder /bin/mail-remote /mail-remote
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/queue-manager"]
CMD ["--config", "/etc/infodancer/config.toml", "--queue", "/var/spool/mail-queue", "--binary", "/mail-remote"]
