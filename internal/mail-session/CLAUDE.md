# template-go

Go project template with CI pipeline.

## Build

```bash
go build ./...
```

## Test

```bash
go test -race ./...
```

## Lint

```bash
# Requires golangci-lint v2
golangci-lint run ./...
```

## Vulnerability Check

```bash
govulncheck ./...
```
