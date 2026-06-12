package maildir

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	mserrors "github.com/infodancer/maildancer/msgstore/errors"
)

func TestSieveScript(t *testing.T) {
	base := t.TempDir()
	store := NewStore(base, "Maildir", "")

	t.Run("missing script returns fs.ErrNotExist", func(t *testing.T) {
		_, err := store.SieveScript(context.Background(), "alice@example.com")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("want fs.ErrNotExist, got %v", err)
		}
	})

	t.Run("existing script is returned", func(t *testing.T) {
		userDir := filepath.Join(base, "alice")
		if err := os.MkdirAll(userDir, 0755); err != nil {
			t.Fatal(err)
		}
		script := "require \"fileinto\";\nfileinto \"Archive\";\n"
		if err := os.WriteFile(filepath.Join(userDir, ".sieve"), []byte(script), 0644); err != nil {
			t.Fatal(err)
		}

		rc, err := store.SieveScript(context.Background(), "alice@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = rc.Close() }()

		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read script: %v", err)
		}
		if string(got) != script {
			t.Errorf("script content mismatch: got %q", got)
		}
	})

	t.Run("path traversal in mailbox is rejected", func(t *testing.T) {
		_, err := store.SieveScript(context.Background(), "../escape@example.com")
		if !errors.Is(err, mserrors.ErrPathTraversal) {
			t.Errorf("want ErrPathTraversal, got %v", err)
		}
	})
}
