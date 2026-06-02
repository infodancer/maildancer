package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// contextKey is the type for context keys in this package.
type contextKey int

const adminKey contextKey = iota

// Entry is a single audit log record.
type Entry struct {
	Time      time.Time `json:"time"`
	Admin     string    `json:"admin"`
	Operation string    `json:"operation"` // e.g. "create_domain", "delete_user", "generate_keys"
	Target    string    `json:"target"`    // e.g. "example.com" or "user@example.com"
	Result    string    `json:"result"`    // "success" or "failure"
	Detail    string    `json:"detail,omitempty"`
}

// Logger writes audit entries as JSON lines to a file and also emits via slog.
type Logger struct {
	mu   sync.Mutex
	path string
	slog *slog.Logger
}

// NewLogger creates a Logger. If path is "", file logging is disabled (slog only).
func NewLogger(path string, slogger *slog.Logger) (*Logger, error) {
	if slogger == nil {
		slogger = slog.Default()
	}
	return &Logger{
		path: path,
		slog: slogger,
	}, nil
}

// WithAdmin returns a context with the admin username stored.
func WithAdmin(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, adminKey, username)
}

// AdminFromContext extracts the admin username from context.
func AdminFromContext(ctx context.Context) string {
	v, _ := ctx.Value(adminKey).(string)
	return v
}

// Log writes an audit entry. Admin username is taken from context if set via WithAdmin.
// Falls back to entry.Admin if context has no admin.
func (l *Logger) Log(ctx context.Context, entry Entry) {
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	if admin := AdminFromContext(ctx); admin != "" {
		entry.Admin = admin
	}

	l.slog.InfoContext(ctx, "audit",
		slog.String("admin", entry.Admin),
		slog.String("operation", entry.Operation),
		slog.String("target", entry.Target),
		slog.String("result", entry.Result),
		slog.String("detail", entry.Detail),
		slog.Time("time", entry.Time),
	)

	if l.path == "" {
		return
	}

	line, err := json.Marshal(entry)
	if err != nil {
		l.slog.Error("audit: failed to marshal entry", slog.String("error", err.Error()))
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.slog.Error("audit: failed to open log file", slog.String("error", err.Error()))
		return
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		l.slog.Error("audit: failed to write log entry", slog.String("error", err.Error()))
	}
}

// ReadRecent reads up to n most-recent entries from the log file.
// Returns empty slice if path is unset or file doesn't exist.
func (l *Logger) ReadRecent(n int) ([]Entry, error) {
	if l.path == "" {
		return []Entry{}, nil
	}

	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		all = append(all, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if n >= len(all) {
		return all, nil
	}
	return all[len(all)-n:], nil
}
