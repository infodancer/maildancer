# template-go

Opinionated Go project template with a battle-tested CI pipeline.

## Usage

1. Click **Use this template** on GitHub (or `gh repo create --template matthewjhunter/template-go`)
2. Rename `cmd/appname/` to match your binary name
3. Update `module` path in `go.mod`
4. Update `BINARY` in `Taskfile.yml`, `main`/`binary` in `.goreleaser.yml`, and the binary name in `.gitignore`
5. Update `REPO_NAME` in `SECURITY.md`
6. Run `task hooks:install` to set up git hooks

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

### Task Runner

A [Taskfile](https://taskfile.dev/) wraps all CI checks for local use:

```bash
task check      # Run all CI checks locally
task test       # Tests with race detector
task lint       # golangci-lint
task vulncheck  # govulncheck
```

### Git Hooks

Two git hooks keep code clean locally:

- **Pre-commit**: auto-formats staged `.go` files with `gofmt`
- **Pre-push**: runs test, vet, lint, and govulncheck before pushing

Install both with:

```bash
task hooks:install
```

### Releases

Tag a version to trigger a release build via [GoReleaser](https://goreleaser.com/):

```bash
git tag v0.1.0
git push origin v0.1.0
```

Builds cross-platform binaries (linux/darwin, amd64/arm64) with checksums and a changelog.

### Dependency Management

Dependabot is configured for weekly updates to both Go modules and GitHub Actions.

### Security & Issues

- **`SECURITY.md`** — vulnerability reporting instructions via GitHub's private advisory system
- **Issue templates** — structured bug report and feature request forms

### Project Structure

```
cmd/appname/    # CLI entrypoint (rename to your binary)
internal/       # Private packages
githooks/       # Git hooks (install with task hooks:install)
```

## Customization

- **Linters**: Edit `.golangci.yml` to enable additional linters
- **CI triggers**: Edit `.github/workflows/ci.yml` to add branch patterns
- **Release targets**: Edit `.goreleaser.yml` to add OS/arch combinations or change the archive format
- **System dependencies**: If your project needs C libraries, add an `apt-get install` step to the test, vet, lint, and govulncheck jobs

## License

MIT
