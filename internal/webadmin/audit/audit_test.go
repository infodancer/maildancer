package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewLogger_NoPath(t *testing.T) {
	l, err := NewLogger("", slog.Default())
	if err != nil {
		t.Fatalf("NewLogger with empty path: %v", err)
	}
	// Log should not panic or error with no file path
	l.Log(context.Background(), Entry{
		Operation: "test_op",
		Target:    "test_target",
		Result:    "success",
	})
}

func TestLog_WritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewLogger(path, slog.Default())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	entry := Entry{
		Admin:     "admin@example.com",
		Operation: "create_domain",
		Target:    "example.com",
		Result:    "success",
		Detail:    "some detail",
	}
	l.Log(context.Background(), entry)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal JSON line: %v", err)
	}

	if got.Admin != entry.Admin {
		t.Errorf("Admin: got %q, want %q", got.Admin, entry.Admin)
	}
	if got.Operation != entry.Operation {
		t.Errorf("Operation: got %q, want %q", got.Operation, entry.Operation)
	}
	if got.Target != entry.Target {
		t.Errorf("Target: got %q, want %q", got.Target, entry.Target)
	}
	if got.Result != entry.Result {
		t.Errorf("Result: got %q, want %q", got.Result, entry.Result)
	}
	if got.Detail != entry.Detail {
		t.Errorf("Detail: got %q, want %q", got.Detail, entry.Detail)
	}
	if got.Time.IsZero() {
		t.Error("Time should not be zero")
	}
}

func TestLog_AdminFromContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewLogger(path, slog.Default())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	ctx := WithAdmin(context.Background(), "ctxadmin")
	l.Log(ctx, Entry{
		Operation: "delete_user",
		Target:    "user@example.com",
		Result:    "success",
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Admin != "ctxadmin" {
		t.Errorf("Admin: got %q, want %q", got.Admin, "ctxadmin")
	}
}

func TestLog_Concurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewLogger(path, slog.Default())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	const goroutines = 10
	const logsEach = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < logsEach; j++ {
				l.Log(context.Background(), Entry{
					Operation: "concurrent_op",
					Target:    "target",
					Result:    "success",
				})
			}
		}()
	}
	wg.Wait()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d corrupt JSON: %v | line: %s", count+1, err, line)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}

	expected := goroutines * logsEach
	if count != expected {
		t.Errorf("line count: got %d, want %d", count, expected)
	}
}

func TestReadRecent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewLogger(path, slog.Default())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	operations := []string{"op1", "op2", "op3", "op4", "op5"}
	for _, op := range operations {
		l.Log(context.Background(), Entry{
			Operation: op,
			Target:    "target",
			Result:    "success",
			Time:      time.Now(),
		})
	}

	entries, err := l.ReadRecent(3)
	if err != nil {
		t.Fatalf("ReadRecent: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("ReadRecent(3): got %d entries, want 3", len(entries))
	}

	// Should be last 3 in order: op3, op4, op5
	want := []string{"op3", "op4", "op5"}
	for i, e := range entries {
		if e.Operation != want[i] {
			t.Errorf("entry[%d].Operation: got %q, want %q", i, e.Operation, want[i])
		}
	}
}

func TestReadRecent_NoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.log")

	l, err := NewLogger(path, slog.Default())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	entries, err := l.ReadRecent(10)
	if err != nil {
		t.Fatalf("ReadRecent on non-existent file: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(entries))
	}
}

func TestReadRecent_AllEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewLogger(path, slog.Default())
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	for i := 0; i < 5; i++ {
		l.Log(context.Background(), Entry{
			Operation: "op",
			Target:    "target",
			Result:    "success",
		})
	}

	entries, err := l.ReadRecent(100)
	if err != nil {
		t.Fatalf("ReadRecent(100): %v", err)
	}
	if len(entries) != 5 {
		t.Errorf("ReadRecent(100) with 5 entries: got %d, want 5", len(entries))
	}
}

func TestAdminFromContext_Empty(t *testing.T) {
	admin := AdminFromContext(context.Background())
	if admin != "" {
		t.Errorf("expected empty string, got %q", admin)
	}
}

func TestWithAdmin_RoundTrip(t *testing.T) {
	ctx := WithAdmin(context.Background(), "someadmin")
	got := AdminFromContext(ctx)
	if got != "someadmin" {
		t.Errorf("AdminFromContext: got %q, want %q", got, "someadmin")
	}
}
