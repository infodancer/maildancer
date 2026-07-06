package liblog

import (
	"log/slog"
	"testing"
)

func TestLevel(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want slog.Level
	}{
		// Benign, client-caused -> info.
		{"malformed command (prod signature)", `failed to read command: in command: imapwire: expected SP, got "\r"`, slog.LevelInfo},
		{"greeting EOF (probe/health check)", "failed to write greeting: EOF", slog.LevelInfo},
		{"greeting TLS mismatch", "failed to write greeting: tls: client offered only unsupported versions: [302 301]", slog.LevelInfo},
		{"close session teardown", "failed to close session: use of closed network connection", slog.LevelInfo},
		{"go-smtp per-connection error", "error handling 1.2.3.4:2525: read: connection reset by peer", slog.LevelInfo},

		// Genuine faults -> error (must not be demoted).
		{"go-imap SERVERBUG cause (#131 signal)", "handling FETCH command: internal boom", slog.LevelError},
		{"go-imap panic", "panic handling command: boom\ngoroutine 1 ...", slog.LevelError},
		{"go-imap idle panic", "panic idling: boom", slog.LevelError},
		{"go-smtp panic", "panic serving 1.2.3.4: boom\ngoroutine 1 ...", slog.LevelError},
		{"go-imap session create failure", "failed to create session: backend down", slog.LevelError},
		{"go-smtp listener accept error", "accept error: too many open files; retrying in 5ms", slog.LevelError},
		{"unknown message", "something entirely unexpected", slog.LevelError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Level(tc.msg); got != tc.want {
				t.Errorf("Level(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}
