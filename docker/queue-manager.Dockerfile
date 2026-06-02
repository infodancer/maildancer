# queue-manager — outbound mail queue driver. Bundles the mail-remote agent it
# invokes per delivery. Build from the repo root:
#   docker build -f docker/queue-manager.Dockerfile -t maildancer-queue-manager .
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/queue-manager ./cmd/queue-manager
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mail-remote ./cmd/mail-remote

FROM scratch
COPY --from=builder /out/queue-manager /queue-manager
COPY --from=builder /out/mail-remote /mail-remote
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/queue-manager"]
CMD ["--config", "/etc/infodancer/config.toml", "--queue", "/var/spool/mail-queue", "--binary", "/mail-remote"]
