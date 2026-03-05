# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o imapd ./cmd/imapd
# Create /tmp with sticky bit for os.CreateTemp in the scratch runtime
RUN mkdir -p /tmp && chmod 1777 /tmp

# Runtime stage
FROM scratch
COPY --from=builder /build/imapd /imapd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp /tmp
EXPOSE 143 993 9102
ENTRYPOINT ["/imapd"]
CMD ["--config", "/etc/infodancer/config.toml"]
