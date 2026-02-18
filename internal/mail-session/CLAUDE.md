# template-go

Go project template with CI pipeline.

## First Use

When starting a new project from this template, make these changes:

1. **Module path**: Update `module` in `go.mod` to match the new repository (e.g., `github.com/matthewjhunter/myproject`).
2. **Binary name**: Rename `cmd/appname/` to the desired binary name. Update the `BINARY` var in `Taskfile.yml` and the binary entry in `.gitignore` to match.
3. **License**: The template includes an MIT license. Confirm this is the desired license; replace `LICENSE` if not.
4. **GoReleaser**: Update `main` and `binary` in `.goreleaser.yml` to match the binary name.
5. **SECURITY.md**: Replace `REPO_NAME` in the advisory URL with the actual repository name.
6. **Issue templates**: Update the placeholder `appname` in `.github/ISSUE_TEMPLATE/bug_report.yml`.
7. **Git hooks**: Run `task hooks:install` to install the pre-commit and pre-push hooks.
8. **README**: Replace the template README with project-specific content.
9. **This file**: Update this CLAUDE.md — remove this "First Use" section and add project-specific build/test instructions.

## Build

```bash
go build ./...

# Or via Task
task build
```

## Test

```bash
go test -race ./...

# Or via Task
task test
```

## Lint

```bash
# Requires golangci-lint v2
golangci-lint run ./...

# Or via Task
task lint
```

## Vulnerability Check

```bash
govulncheck ./...

# Or via Task
task vulncheck
```

## All CI Checks

```bash
task check
```
