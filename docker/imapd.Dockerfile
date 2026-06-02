# imapd — IMAP server. Build from the repo root:
#   docker build -f docker/imapd.Dockerfile -t maildancer-imapd .
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/imapd ./cmd/imapd
# /tmp with sticky bit for os.CreateTemp in the scratch runtime.
RUN mkdir -p /out/tmp && chmod 1777 /out/tmp

FROM scratch
COPY --from=builder /out/imapd /imapd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/tmp /tmp
EXPOSE 143 993 9102
ENTRYPOINT ["/imapd"]
CMD ["--config", "/etc/infodancer/config.toml"]
