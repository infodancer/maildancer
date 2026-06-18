package domain

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/infodancer/maildancer/auth/passwd"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
)

// capturingHandler records every slog.Record it is given, at all levels.
type capturingHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// TestGetDomain_UnreadableForwardsFile_LogsDebugNotWarn verifies #98: when the
// per-domain forwards file cannot be read (the expected case in the
// privilege-dropped mail-session), GetDomain degrades to an empty domain tier,
// still loads the domain, and logs at Debug rather than Warn -- no per-delivery
// log noise.
func TestGetDomain_UnreadableForwardsFile_LogsDebugNotWarn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions; cannot exercise the EACCES path")
	}

	tmpDir := t.TempDir()
	domainDir := filepath.Join(tmpDir, "example.com")
	for _, d := range []string{"keys", "maildir"} {
		if err := os.MkdirAll(filepath.Join(domainDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte("# none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "[auth]\ntype = \"passwd\"\ncredential_backend = \"passwd\"\nkey_backend = \"keys\"\n\n[msgstore]\ntype = \"maildir\"\nbase_path = \"maildir\"\n"
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// A forwards file that cannot be read (mode 0000).
	if err := os.WriteFile(filepath.Join(domainDir, "forwards"), []byte("alice:elsewhere@example.org\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	capH := &capturingHandler{}
	provider := NewFilesystemDomainProvider(tmpDir, slog.New(capH))
	t.Cleanup(func() { _ = provider.Close() })

	d := provider.GetDomain("example.com")
	if d == nil {
		t.Fatal("GetDomain returned nil; an unreadable forwards file must degrade gracefully, not fail the load")
	}

	capH.mu.Lock()
	defer capH.mu.Unlock()
	var sawDebug bool
	for _, r := range capH.recs {
		msg := strings.ToLower(r.Message)
		if !strings.Contains(msg, "forwards file") {
			continue
		}
		if r.Level >= slog.LevelWarn {
			t.Errorf("forwards-file read failure logged at %s, want Debug: %q", r.Level, r.Message)
		}
		if r.Level == slog.LevelDebug {
			sawDebug = true
		}
	}
	if !sawDebug {
		t.Error("expected a Debug log for the skipped unreadable forwards file")
	}
}
