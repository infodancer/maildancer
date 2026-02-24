# Build from the parent infodancer/ directory to resolve local module replacements:
#   docker build -f webadmin/Dockerfile -t webadmin .

FROM golang:1.24 AS builder

WORKDIR /src

# Copy module files first for layer caching
COPY auth/go.mod auth/go.sum ./auth/
COPY msgstore/go.mod msgstore/go.sum ./msgstore/
COPY webadmin/go.mod webadmin/go.sum ./webadmin/

WORKDIR /src/webadmin
RUN go mod download

# Copy source for all required modules
WORKDIR /src
COPY auth/ ./auth/
COPY msgstore/ ./msgstore/
COPY webadmin/ ./webadmin/

WORKDIR /src/webadmin
RUN CGO_ENABLED=0 go build -o /webadmin ./cmd/webadmin

FROM gcr.io/distroless/static-debian12

COPY --from=builder /webadmin /webadmin

EXPOSE 8080

ENTRYPOINT ["/webadmin"]
CMD ["-config", "/etc/webadmin/webadmin.toml"]
