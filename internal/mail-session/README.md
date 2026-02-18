# template-go

Opinionated Go project template with a battle-tested CI pipeline.

## Usage

1. Click **Use this template** on GitHub (or `gh repo create --template matthewjhunter/template-go`)
2. Rename `cmd/appname/` to match your binary name
3. Update `module` path in `go.mod`
4. Update the binary name in `.gitignore`

## What's Included

### CI Pipeline

All jobs run on every push to `main` and on pull requests:

| Job | What it does |
|-----|-------------|
| **test** | `go test -race -count=1 ./...` — race detector enabled, no test caching |
| **vet** | `go vet ./...` — built-in static analysis |
| **fmt** | `gofmt -l .` — enforces canonical formatting |
| **lint** | golangci-lint v2 with focused linter set (govet, staticcheck, unused, ineffassign) |
| **govulncheck** | Scans stdlib and dependencies for known vulnerabilities |

### Dependency Management

Dependabot is configured for weekly updates to both Go modules and GitHub Actions.

### Project Structure

```
cmd/appname/    # CLI entrypoint (rename to your binary)
internal/       # Private packages
```

## Customization

- **Linters**: Edit `.golangci.yml` to enable additional linters
- **CI triggers**: Edit `.github/workflows/ci.yml` to add branch patterns
- **System dependencies**: If your project needs C libraries, add an `apt-get install` step to the test, vet, lint, and govulncheck jobs

## License

MIT
