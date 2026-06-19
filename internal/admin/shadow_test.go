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
	t.Run("exact forward of a real user is intentional, not flagged", func(t *testing.T) {
		p := newTestPaths(t)
		// A real mailbox that forwards elsewhere is the classic forwarding case.
		writeDomainFixture(t, p, "example.com",
			"alice:hash:alice\nbob:hash:bob\n",
			"[forwards]\nalice = \"alice@elsewhere.com\"\n", "")

		if w := p.shadowWarnings("example.com"); len(w) != 0 {
			t.Errorf("exact forward must not be flagged, got %v", w)
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
		if !strings.Contains(warnings[0], "catchall (*)") {
			t.Errorf("warning should name the catchall: %q", warnings[0])
		}
	})

	t.Run("exact forward overrides catchall: only the swept user is flagged", func(t *testing.T) {
		p := newTestPaths(t)
		// alice has her own explicit forward (intentional); bob is only caught
		// by the catchall (the surprising case).
		writeDomainFixture(t, p, "example.com",
			"alice:hash:alice\nbob:hash:bob\n",
			"", "alice:alice@elsewhere.com\n*:catchall@elsewhere.com\n")

		warnings := p.shadowWarnings("example.com")
		if len(warnings) != 1 {
			t.Fatalf("want 1 warning (bob only), got %d: %v", len(warnings), warnings)
		}
		if !strings.Contains(warnings[0], "bob@example.com") {
			t.Errorf("warning should be for bob, got %q", warnings[0])
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
