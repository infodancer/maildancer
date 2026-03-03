FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /auth-oidc ./cmd/auth-oidc

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /auth-oidc /auth-oidc

ENTRYPOINT ["/auth-oidc"]
CMD ["serve"]
