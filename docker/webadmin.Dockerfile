# webadmin — web administration UI. Build from the repo root:
#   docker build -f docker/webadmin.Dockerfile -t maildancer-webadmin .
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/webadmin ./cmd/webadmin

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/webadmin /webadmin
EXPOSE 8080
ENTRYPOINT ["/webadmin"]
