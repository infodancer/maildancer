 CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a template repository for go projects.

## Development Commands

## Architecture

## Development Workflow

### Branch and Issue Protocol

**This workflow is MANDATORY.** All significant work must follow this process with no exceptions:

1. **Create a GitHub issue first** - Before creating a branch, draft an issue describing the purpose and design based on your understanding of the user's request. Assign the issue to the user who requested it. Ask the user to approve the issue before proceeding.  Refer back to the issue if necessary.

2. **Create a feature or content branch** - Only after issue approval, create the branch. Use descriptive names that include the issue id like `feature/UUID` or `bug/UUID`.

3. **Reference the issue in all commits** - Every commit message and pull request must include the issue URL.

4. **Stay focused on the issue** - Make only changes directly related to the approved issue. Do not refactor unrelated code, fix unrelated bugs, or make "improvements" outside the scope.

5. **Handle unrelated problems separately** - If you notice bugs, technical debt, or potential issues unrelated to your current work, ask the user to approve creating a separate GitHub issue. Do not address them in the current branch.

## Best Practices

### Commit Practices

- Atomic commits - one logical change per commit
- Build/verify locally before committing 

### Pull Request Workflow

- All branches merge to main via PR
- PRs should reference the originating issue
- Squash or rebase to keep history clean
- **NEVER ask users to merge or approve a PR** - PR approval and merging must always be manual actions taken by the user. Do not prompt, suggest, or automate this step.
- After creating a PR, checkout the main branch before starting any further work.

### Security Best Practices

#### Secrets Management
- Never commit secrets, API keys, credentials, or tokens
- Use environment variables or secret management tools for sensitive configuration
- Add sensitive file patterns to `.gitignore` (`.env`, `*.pem`, `*.key`, `credentials.*`)
- Rotate secrets immediately if accidentally committed (treat as compromised)

#### Input Validation & Sanitization
- Validate all external input at system boundaries
- Sanitize user input before use in SQL queries, shell commands, or templates
- Use parameterized queries to prevent SQL injection
- Avoid constructing shell commands from user input (command injection risk)

#### Dependency Security
- Regularly audit dependencies with `go mod tidy` and vulnerability scanners (`govulncheck`)
- Pin dependency versions in `go.mod`
- Review new dependencies before adding them to the project
- Keep dependencies updated for security patches

#### Secure Coding Practices
- Avoid `unsafe` package unless absolutely necessary
- Use `crypto/rand` for random number generation in security contexts (not `math/rand`)
- Implement proper authentication and authorization checks
- Plan for TLS in production; document when HTTP is intentionally used for local development
- Set appropriate timeouts on network operations to prevent resource exhaustion

#### Error Handling Security
- Never expose internal error details to end users
- Log detailed errors server-side only
- Avoid leaking sensitive data in error messages or logs

Read CONVENTIONS.md for language specific best practices.
