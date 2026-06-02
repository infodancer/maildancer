# smtpd — SMTP server. Build from the repo root:
#   docker build -f docker/smtpd.Dockerfile -t maildancer-smtpd .
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/smtpd ./cmd/smtpd
# /tmp with sticky bit for os.CreateTemp in the scratch runtime.
RUN mkdir -p /out/tmp && chmod 1777 /out/tmp

FROM scratch
COPY --from=builder /out/smtpd /smtpd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/tmp /tmp
EXPOSE 25 465 587 9100
ENTRYPOINT ["/smtpd"]
CMD ["--config", "/etc/infodancer/config.toml"]
