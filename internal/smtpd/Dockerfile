# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
# Strip local replace directives so Go fetches published module versions
RUN go mod edit -dropreplace=github.com/infodancer/maildancer/msgstore
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o smtpd ./cmd/smtpd
# Create /tmp with sticky bit for os.CreateTemp in the scratch runtime
RUN mkdir -p /tmp && chmod 1777 /tmp

# Runtime stage
FROM scratch
COPY --from=builder /build/smtpd /smtpd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp /tmp
EXPOSE 25 465 587 9100
ENTRYPOINT ["/smtpd"]
CMD ["--config", "/etc/infodancer/config.toml"]
