FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /auth-oidc ./cmd/auth-oidc

# Staged data dir so the final image owns /var/lib/auth-oidc as nonroot.
# Docker propagates image-side ownership to a fresh named-volume mount, which
# lets UID 65532 create oidc-state.db on first boot without a host-side chown.
RUN mkdir -p /staging/var/lib/auth-oidc

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /auth-oidc /auth-oidc
COPY --from=builder --chown=nonroot:nonroot /staging/var/lib/auth-oidc /var/lib/auth-oidc

ENTRYPOINT ["/auth-oidc"]
CMD ["serve"]
