# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o pop3d ./cmd/pop3d

# Runtime stage
FROM scratch
COPY --from=builder /build/pop3d /pop3d
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 110 995 9100
ENTRYPOINT ["/pop3d"]
CMD ["--config", "/etc/infodancer/config.toml"]
