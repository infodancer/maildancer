package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDomainFixture creates a config-tree domain directory with the given
// passwd lines, config.toml body, and optional forwards-file body.
func writeDomainFixture(t *testing.T, p Paths, domainName, passwdBody, configBody, forwardsBody string) {
	t.Helper()
	domainDir := filepath.Join(p.Config, domainName)
	if err := os.MkdirAll(domainDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "passwd"), []byte(passwdBody), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domainDir, "config.toml"), []byte(configBody), 0o640); err != nil {
		t.Fatal(err)
	}
	if forwardsBody != "" {
		if err := os.WriteFile(filepath.Join(domainDir, "forwards"), []byte(forwardsBody), 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func TestShadowWarnings(t *testing.T) {
	t.Run("admin tier exact forward shadows a real user", func(t *testing.T) {
		p := newTestPaths(t)
		writeDomainFixture(t, p, "example.com",
			"alice:hash:alice\nbob:hash:bob\n",
			"[forwards]\nalice = \"alice@elsewhere.com\"\n", "")

		warnings := p.shadowWarnings("example.com")
		if len(warnings) != 1 {
			t.Fatalf("want 1 warning, got %d: %v", len(warnings), warnings)
		}
		if !strings.Contains(warnings[0], "alice@example.com") || !strings.Contains(warnings[0], "alice@elsewhere.com") {
			t.Errorf("warning missing user or target: %q", warnings[0])
		}
	})

	t.Run("domain catchall shadows every real user", func(t *testing.T) {
		p := newTestPaths(t)
		writeDomainFixture(t, p, "example.com",
			"alice:hash:alice\nbob:hash:bob\n",
			"", "*:catchall@elsewhere.com\n")

		warnings := p.shadowWarnings("example.com")
		if len(warnings) != 2 {
			t.Fatalf("want 2 warnings (catchall shadows all), got %d: %v", len(warnings), warnings)
		}
	})

	t.Run("no forwards, no warnings", func(t *testing.T) {
		p := newTestPaths(t)
		writeDomainFixture(t, p, "example.com", "alice:hash:alice\n", "", "")

		if w := p.shadowWarnings("example.com"); len(w) != 0 {
			t.Errorf("want no warnings, got %v", w)
		}
	})

	t.Run("forward-only address (no passwd user) is not shadowed", func(t *testing.T) {
		p := newTestPaths(t)
		// alias is a pure forward with no mailbox -- not a shadow, just a forward.
		writeDomainFixture(t, p, "example.com",
			"# no users\n",
			"[forwards]\nalias = \"real@elsewhere.com\"\n", "")

		if w := p.shadowWarnings("example.com"); len(w) != 0 {
			t.Errorf("want no warnings for forward-only address, got %v", w)
		}
	})
}
