package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// TestIMAPLogger_LogsUnderlyingErrorAtErrorLevel verifies that the adapter we
// hand to go-imap's imapserver.Logger surfaces internal faults -- including the
// "handling <CMD> command" errors it converts into "NO [SERVERBUG]" client
// responses -- as structured, error-level records rather than dropping them
// into log.Default(). Regression test for issue #131.
func TestIMAPLogger_LogsUnderlyingErrorAtErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// This is exactly the format go-imap uses at conn.go:309 right before it
	// replaces the response with internalServerErrorResp (the SERVERBUG).
	imapLogger{logger: logger}.Printf("handling %v command: %v", "FETCH", errors.New("boom"))

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("log output is not valid JSON: %v (%q)", err, buf.String())
	}
	if rec["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", rec["level"])
	}
	if msg, _ := rec["msg"].(string); !strings.Contains(msg, "handling FETCH command: boom") {
		t.Errorf("msg = %q, want it to contain the formatted underlying error", msg)
	}
}
