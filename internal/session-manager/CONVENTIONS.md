# Go (Golang) Development Conventions

These conventions ensure a scalable, maintainable, and clean Go codebase that prioritizes simplicity, modularity, and readability. They integrate modern Go best practices, including concurrency, error management, and project organization.

---

## 1. Project Structure

Use the following pattern for scalable Go applications:

```plaintext
/cmd
  /<appname>     # Main application entrypoint(s), minimal logic (calls /internal)
/internal
  /<module>      # Each domain or feature as a separate module
    handlers.go
    service.go
    repository.go
    model.go
/errors
  errors.go      # Centralized error definitions and handling
```

- Place only the main entrypoint in `/cmd/<appname>/main.go`.
- Keep all implementation logic within `/internal` modules.
- All error handling and logging are centralized.

---

## 2. Modularity & Simplicity

- **Single Responsibility:** Every file, type, and function should do one thing.
- **Short Functions:** Keep functions under 30 lines when possible.
- **Descriptive Names:** Use meaningful file, type, and function names (follow [Google Go standards](https://google.github.io/styleguide/go/decisions)).

---

## 3. Concurrency

- Use goroutines and channels where suitable (for parallelism and asynchronous tasks).
- Avoid concurrency when it makes code less readable or more complex.
- Always document concurrent code for clarity.

---

## 4. Error Management

- **Centralize Errors:** Define all error types and helpers in `/errors/errors.go`.
- **Propagate Errors:** Always return errors to a single handling point.
- **Error Wrapping:** Use Go's error wrapping (`fmt.Errorf("context: %w", err)`) for stack traces.
- **No Silent Failures:** Always check and return errors, never ignore them.

---

## 5. Logging

- Use `log/slog` for structured logging throughout.
- Keep log messages meaningful and context-rich.

---

## 6. Code Quality

- **DRY:** Avoid duplication—use helpers or utility packages for repeated logic.
- **Readability:** Prefer clarity over cleverness.
- **Scalability:** Organize code so new features can be added without major refactoring.

---

## 7. Security Best Practices

- Never commit secrets, API keys, credentials, or tokens.
- Use `crypto/rand` for random number generation in security contexts.
- Validate all external input at system boundaries.
- Set appropriate timeouts on network operations.

---

## 8. References

- [Go Project Layout](https://github.com/golang-standards/project-layout)
- [Google Go Style Guide](https://google.github.io/styleguide/go/decisions)
- [Effective Go](https://go.dev/doc/effective_go)
