# Build stage: session-manager
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o session-manager ./cmd/session-manager

# Build stage: mail-session
FROM golang:1.26-alpine AS mail-session-builder
RUN CGO_ENABLED=0 go install github.com/infodancer/maildancer/internal/mail-session/cmd/mail-session@v0.1.5

# Create /tmp with sticky bit for child process use in the scratch runtime
RUN mkdir -p /tmp && chmod 1777 /tmp

# Runtime stage
FROM scratch
COPY --from=builder /build/session-manager /session-manager
COPY --from=mail-session-builder /go/bin/mail-session /mail-session
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=mail-session-builder /tmp /tmp
ENTRYPOINT ["/session-manager"]
CMD ["--config", "/etc/infodancer/config.toml"]
