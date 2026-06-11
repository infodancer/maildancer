# auth-oidc -- leaf OIDC identity provider for owned mail domains. Build from the
# repo root:
#   docker build -f docker/auth-oidc.Dockerfile -t maildancer-auth-oidc .
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-oidc ./cmd/auth-oidc
# Staged data dir so the final image owns /var/lib/auth-oidc as nonroot. Docker
# propagates image-side ownership to a fresh named-volume mount, letting
# UID 65532 create oidc-state.db on first boot without a host-side chown.
RUN mkdir -p /staging/var/lib/auth-oidc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/auth-oidc /auth-oidc
COPY --from=builder --chown=nonroot:nonroot /staging/var/lib/auth-oidc /var/lib/auth-oidc
ENTRYPOINT ["/auth-oidc"]
CMD ["serve"]
