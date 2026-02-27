package forwards_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infodancer/maildancer/auth/forwards"
)

func TestLoad_MissingFile(t *testing.T) {
	m, err := forwards.Load("/nonexistent/path/forwards")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if !m.Empty() {
		t.Error("expected empty map for missing file")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwards")
	if err := os.WriteFile(path, []byte("# comment only\n\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := forwards.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Empty() {
		t.Error("expected empty map")
	}
}

func TestLoad_ExactMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwards")
	content := "alice:alice@other.com\nbob:bob@other.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := forwards.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	targets, ok := m.Resolve("alice")
	if !ok {
		t.Fatal("expected forward for alice")
	}
	if len(targets) != 1 || targets[0] != "alice@other.com" {
		t.Errorf("unexpected targets for alice: %v", targets)
	}

	if !m.UserExists("bob") {
		t.Error("expected UserExists true for bob")
	}
	if m.UserExists("charlie") {
		t.Error("expected UserExists false for charlie (no catchall)")
	}
}

func TestLoad_Catchall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwards")
	content := "*:catchall@example.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := forwards.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	targets, ok := m.Resolve("anyone")
	if !ok {
		t.Fatal("expected catchall to match")
	}
	if len(targets) != 1 || targets[0] != "catchall@example.com" {
		t.Errorf("unexpected catchall targets: %v", targets)
	}
}

func TestLoad_ExactBeforeCatchall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwards")
	content := "alice:specific@example.com\n*:catchall@example.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := forwards.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Exact match should win over catchall
	targets, ok := m.Resolve("alice")
	if !ok || len(targets) != 1 || targets[0] != "specific@example.com" {
		t.Errorf("expected specific target for alice, got %v ok=%v", targets, ok)
	}

	// Others get catchall
	targets, ok = m.Resolve("bob")
	if !ok || len(targets) != 1 || targets[0] != "catchall@example.com" {
		t.Errorf("expected catchall for bob, got %v ok=%v", targets, ok)
	}
}

func TestLoad_MultipleTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwards")
	content := "alice:a@one.com, b@two.com, c@three.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := forwards.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	targets, ok := m.Resolve("alice")
	if !ok {
		t.Fatal("expected forward for alice")
	}
	if len(targets) != 3 {
		t.Errorf("expected 3 targets, got %d: %v", len(targets), targets)
	}
}

func TestLoad_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forwards")
	content := "Alice:alice@other.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := forwards.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Lookup should be case-insensitive
	if !m.UserExists("alice") {
		t.Error("expected match for lowercase alice")
	}
	if !m.UserExists("ALICE") {
		t.Error("expected match for uppercase ALICE")
	}
}

func TestLoadTargets_MissingFile(t *testing.T) {
	targets, err := forwards.LoadTargets("/nonexistent/path/matthew")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected nil targets, got %v", targets)
	}
}

func TestLoadTargets_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "matthew")
	content := "matthew@matthewjayhunter.com\n# comment\nmatthew@infodancer.net\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	targets, err := forwards.LoadTargets(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d: %v", len(targets), targets)
	}
	if targets[0] != "matthew@matthewjayhunter.com" || targets[1] != "matthew@infodancer.net" {
		t.Errorf("unexpected targets: %v", targets)
	}
}

func TestForwardMap_NilSafe(t *testing.T) {
	var m *forwards.ForwardMap
	_, ok := m.Resolve("anyone")
	if ok {
		t.Error("nil ForwardMap.Resolve should return false")
	}
	if !m.Empty() {
		t.Error("nil ForwardMap.Empty should return true")
	}
}
