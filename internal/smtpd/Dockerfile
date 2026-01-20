# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o smtpd ./cmd/smtpd

# Runtime stage
FROM scratch
COPY --from=builder /build/smtpd /smtpd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 25 465 587 9100
ENTRYPOINT ["/smtpd"]
CMD ["--config", "/etc/infodancer/config.toml"]
