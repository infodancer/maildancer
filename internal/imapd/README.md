# imapd

An IMAP server implementation in Go.

## Prerequisites

- [Go](https://go.dev/) 1.25 or later
- [Task](https://taskfile.dev/) - task runner
- [golangci-lint](https://golangci-lint.run/) - linter
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - vulnerability scanner

## Development

### Available Tasks

| Task | Description |
|------|-------------|
| `task build` | Build the binary |
| `task test` | Run tests with race detector |
| `task vet` | Run go vet |
| `task fmt` | Check formatting |
| `task fmt:fix` | Fix formatting |
| `task lint` | Run golangci-lint |
| `task vulncheck` | Run govulncheck |
| `task check` | Run all CI checks |
| `task clean` | Remove build artifacts |
| `task hooks:install` | Install git hooks |

### Git Hooks

A pre-commit hook auto-formats staged Go files. A pre-push hook runs the full CI check suite before pushing.

```bash
task hooks:install
```

### Releases

Tag a version to trigger a release build:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Builds cross-platform binaries (linux/darwin, amd64/arm64) via GoReleaser.
