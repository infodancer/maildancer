# session-manager -- authenticates and proxies per-user mail sessions. Bundles
# the mail-session agent it spawns (uid/gid set per user at spawn time).
# Build from the repo root:
#   docker build -f docker/session-manager.Dockerfile -t maildancer-session-manager .
#
# The spawned-agent path is configured via `mail_session_cmd` in config.toml;
# this image places the binary at /mail-session to match the stock config.
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/session-manager ./cmd/session-manager
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mail-session ./cmd/mail-session
# /tmp with sticky bit for child-process temp files in the scratch runtime.
RUN mkdir -p /out/tmp && chmod 1777 /out/tmp

FROM scratch
COPY --from=builder /out/session-manager /session-manager
COPY --from=builder /out/mail-session /mail-session
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/tmp /tmp
ENTRYPOINT ["/session-manager"]
CMD ["--config", "/etc/infodancer/config.toml"]
