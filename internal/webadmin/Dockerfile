FROM golang:1.24.13 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webadmin ./cmd/webadmin

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /build/webadmin /webadmin
EXPOSE 8080
ENTRYPOINT ["/webadmin"]
