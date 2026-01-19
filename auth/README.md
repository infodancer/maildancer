# gotemplate

A golang project template with actions already set up.

## Prerequisites

- [Go](https://go.dev/) 1.23 or later
- [Task](https://taskfile.dev/) - A task runner / simpler Make alternative
- [golangci-lint](https://golangci-lint.run/) - Go linters aggregator
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) - Go vulnerability checker

### Installing Dependencies

Install Task following the [installation instructions](https://taskfile.dev/installation/).

Install Go development tools:

```bash
task install:deps
```

## Development

### Available Tasks

Run `task --list` to see all available tasks:

| Task | Description |
|------|-------------|
| `task build` | Build the Go binary |
| `task lint` | Run golangci-lint |
| `task vulncheck` | Run govulncheck for security vulnerabilities |
| `task test` | Run tests |
| `task test:coverage` | Run tests with coverage report |
| `task all` | Run all checks (build, lint, vulncheck, test) |
| `task clean` | Clean build artifacts |
| `task install:deps` | Install development dependencies |
| `task hooks:install` | Configure git to use project hooks |

### Git Hooks

This project includes a pre-push hook that runs all checks before pushing. To enable it:

```bash
task hooks:install
```

This configures git to use the `.githooks` directory for hooks.
