# pop3d -- POP3 server. Build from the repo root:
#   docker build -f docker/pop3d.Dockerfile -t maildancer-pop3d .
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pop3d ./cmd/pop3d

FROM scratch
COPY --from=builder /out/pop3d /pop3d
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 110 995 9100
ENTRYPOINT ["/pop3d"]
CMD ["--config", "/etc/infodancer/config.toml"]
