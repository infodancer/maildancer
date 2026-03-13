package domain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeepMergeMaps(t *testing.T) {
	t.Run("flat override", func(t *testing.T) {
		base := map[string]any{"a": "1", "b": "2"}
		over := map[string]any{"b": "3", "c": "4"}
		result := deepMergeMaps(base, over)

		if result["a"] != "1" {
			t.Errorf("a = %v, want 1", result["a"])
		}
		if result["b"] != "3" {
			t.Errorf("b = %v, want 3 (overridden)", result["b"])
		}
		if result["c"] != "4" {
			t.Errorf("c = %v, want 4", result["c"])
		}
	})

	t.Run("nested map merge", func(t *testing.T) {
		base := map[string]any{
			"auth": map[string]any{"type": "passwd", "credential_backend": "passwd"},
		}
		over := map[string]any{
			"auth": map[string]any{"type": "ldap"},
		}
		result := deepMergeMaps(base, over)

		auth := result["auth"].(map[string]any)
		if auth["type"] != "ldap" {
			t.Errorf("auth.type = %v, want ldap", auth["type"])
		}
		if auth["credential_backend"] != "passwd" {
			t.Errorf("auth.credential_backend = %v, want passwd (retained from base)", auth["credential_backend"])
		}
	})

	t.Run("override replaces non-map with non-map", func(t *testing.T) {
		base := map[string]any{"gid": int64(1000)}
		over := map[string]any{"gid": int64(2001)}
		result := deepMergeMaps(base, over)
		if result["gid"] != int64(2001) {
			t.Errorf("gid = %v, want 2001", result["gid"])
		}
	})

	t.Run("does not modify base", func(t *testing.T) {
		base := map[string]any{"a": "1"}
		over := map[string]any{"a": "2"}
		deepMergeMaps(base, over)
		if base["a"] != "1" {
			t.Errorf("base was modified: a = %v", base["a"])
		}
	})
}

func TestMergeConfigLayers(t *testing.T) {
	t.Run("basic layer merge", func(t *testing.T) {
		base := map[string]any{
			"gid":                 int64(1000),
			"recipient_rejection": "rcpt",
			"auth": map[string]any{
				"type":               "passwd",
				"credential_backend": "passwd",
			},
		}
		override := map[string]any{
			"gid": int64(2001),
			"auth": map[string]any{
				"type": "ldap",
			},
		}

		var cfg DomainConfig
		if err := mergeConfigLayers(&cfg, base, override); err != nil {
			t.Fatal(err)
		}

		if cfg.Gid != 2001 {
			t.Errorf("Gid = %d, want 2001", cfg.Gid)
		}
		if cfg.RecipientRejection != "rcpt" {
			t.Errorf("RecipientRejection = %q, want rcpt (retained from base)", cfg.RecipientRejection)
		}
		if cfg.Auth.Type != "ldap" {
			t.Errorf("Auth.Type = %q, want ldap", cfg.Auth.Type)
		}
		if cfg.Auth.CredentialBackend != "passwd" {
			t.Errorf("Auth.CredentialBackend = %q, want passwd (retained)", cfg.Auth.CredentialBackend)
		}
	})

	t.Run("three layers", func(t *testing.T) {
		defaults := map[string]any{
			"max_message_size": int64(50 * 1024 * 1024),
			"auth":             map[string]any{"type": "passwd"},
			"limits":           map[string]any{"max_sends_per_hour": int64(100)},
		}
		system := map[string]any{
			"recipient_rejection": "data",
		}
		domain := map[string]any{
			"max_message_size": int64(10 * 1024 * 1024),
		}

		var cfg DomainConfig
		if err := mergeConfigLayers(&cfg, defaults, system, domain); err != nil {
			t.Fatal(err)
		}

		if cfg.MaxMessageSize != 10*1024*1024 {
			t.Errorf("MaxMessageSize = %d, want %d (domain override)", cfg.MaxMessageSize, 10*1024*1024)
		}
		if cfg.RecipientRejection != "data" {
			t.Errorf("RecipientRejection = %q, want data (system layer)", cfg.RecipientRejection)
		}
		if cfg.Auth.Type != "passwd" {
			t.Errorf("Auth.Type = %q, want passwd (defaults)", cfg.Auth.Type)
		}
		if cfg.Limits.MaxSendsPerHour != 100 {
			t.Errorf("Limits.MaxSendsPerHour = %d, want 100 (defaults)", cfg.Limits.MaxSendsPerHour)
		}
	})

	t.Run("nil layers skipped", func(t *testing.T) {
		layer := map[string]any{"gid": int64(42)}
		var cfg DomainConfig
		if err := mergeConfigLayers(&cfg, nil, layer, nil); err != nil {
			t.Fatal(err)
		}
		if cfg.Gid != 42 {
			t.Errorf("Gid = %d, want 42", cfg.Gid)
		}
	})
}

func TestToTOMLMap_OmitsZeroValues(t *testing.T) {
	cfg := DomainConfig{
		Auth: DomainAuthConfig{Type: "passwd"},
		// All other fields are zero — should not appear in map.
	}
	m, err := toTOMLMap(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m["gid"]; ok {
		t.Error("zero-value gid should not appear in TOML map")
	}
	if _, ok := m["max_message_size"]; ok {
		t.Error("zero-value max_message_size should not appear in TOML map")
	}
	if _, ok := m["limits"]; ok {
		t.Error("zero-value limits should not appear in TOML map")
	}

	auth, ok := m["auth"].(map[string]any)
	if !ok {
		t.Fatal("expected auth section in map")
	}
	if auth["type"] != "passwd" {
		t.Errorf("auth.type = %v, want passwd", auth["type"])
	}
}

func TestLoadTOMLMap(t *testing.T) {
	t.Run("missing file returns nil", func(t *testing.T) {
		m, err := loadTOMLMap("/nonexistent/path.toml")
		if err != nil {
			t.Fatal(err)
		}
		if m != nil {
			t.Error("expected nil map for missing file")
		}
	})

	t.Run("valid file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		content := `gid = 2001

[auth]
type = "passwd"

[limits]
max_sends_per_hour = 50
`
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		m, err := loadTOMLMap(path)
		if err != nil {
			t.Fatal(err)
		}
		if m["gid"] != int64(2001) {
			t.Errorf("gid = %v, want 2001", m["gid"])
		}

		limits, ok := m["limits"].(map[string]any)
		if !ok {
			t.Fatal("expected limits section")
		}
		if limits["max_sends_per_hour"] != int64(50) {
			t.Errorf("max_sends_per_hour = %v, want 50", limits["max_sends_per_hour"])
		}
	})
}

func TestMergeConfigLayers_Outbound(t *testing.T) {
	base := map[string]any{
		"outbound": map[string]any{
			"strategy":       "smarthost",
			"smarthost":      "default-relay:587",
			"smarthost_user": "default-user",
			"password_file":  "default-pass",
		},
	}
	override := map[string]any{
		"outbound": map[string]any{
			"smarthost":      "custom-relay:465",
			"smarthost_user": "custom-user",
		},
	}

	var cfg DomainConfig
	if err := mergeConfigLayers(&cfg, base, override); err != nil {
		t.Fatal(err)
	}

	if cfg.Outbound.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost (retained from base)", cfg.Outbound.Strategy)
	}
	if cfg.Outbound.Smarthost != "custom-relay:465" {
		t.Errorf("Smarthost = %q, want custom-relay:465", cfg.Outbound.Smarthost)
	}
	if cfg.Outbound.SmarthostUser != "custom-user" {
		t.Errorf("SmarthostUser = %q, want custom-user", cfg.Outbound.SmarthostUser)
	}
	if cfg.Outbound.PasswordFile != "default-pass" {
		t.Errorf("PasswordFile = %q, want default-pass (retained from base)", cfg.Outbound.PasswordFile)
	}
}

func TestMergeConfigLayers_Limits(t *testing.T) {
	t.Run("global default flows through", func(t *testing.T) {
		global := map[string]any{
			"limits": map[string]any{"max_sends_per_hour": int64(100)},
		}
		var cfg DomainConfig
		if err := mergeConfigLayers(&cfg, global); err != nil {
			t.Fatal(err)
		}
		if cfg.Limits.MaxSendsPerHour != 100 {
			t.Errorf("MaxSendsPerHour = %d, want 100", cfg.Limits.MaxSendsPerHour)
		}
	})

	t.Run("per-domain overrides global", func(t *testing.T) {
		global := map[string]any{
			"limits": map[string]any{"max_sends_per_hour": int64(100)},
		}
		domain := map[string]any{
			"limits": map[string]any{"max_sends_per_hour": int64(25)},
		}
		var cfg DomainConfig
		if err := mergeConfigLayers(&cfg, global, domain); err != nil {
			t.Fatal(err)
		}
		if cfg.Limits.MaxSendsPerHour != 25 {
			t.Errorf("MaxSendsPerHour = %d, want 25 (domain override)", cfg.Limits.MaxSendsPerHour)
		}
	})

	t.Run("domain without limits inherits global", func(t *testing.T) {
		global := map[string]any{
			"limits": map[string]any{"max_sends_per_hour": int64(100)},
		}
		domain := map[string]any{
			"gid": int64(2001),
		}
		var cfg DomainConfig
		if err := mergeConfigLayers(&cfg, global, domain); err != nil {
			t.Fatal(err)
		}
		if cfg.Limits.MaxSendsPerHour != 100 {
			t.Errorf("MaxSendsPerHour = %d, want 100 (inherited from global)", cfg.Limits.MaxSendsPerHour)
		}
	})
}

func TestMergeConfigLayers_FullHierarchy(t *testing.T) {
	// Simulate the full 4-layer hierarchy:
	// programmatic defaults → system config.toml → domains.toml → per-domain config.toml

	dir := t.TempDir()

	// System config.toml
	sysConfigPath := filepath.Join(dir, "system-config.toml")
	sysContent := `
recipient_rejection = "data"

[limits]
max_sends_per_hour = 100
`
	if err := os.WriteFile(sysConfigPath, []byte(sysContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Per-domain config.toml
	domConfigPath := filepath.Join(dir, "domain-config.toml")
	domContent := `
[limits]
max_sends_per_hour = 25
`
	if err := os.WriteFile(domConfigPath, []byte(domContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Programmatic defaults
	defaults := DomainConfig{
		Auth: DomainAuthConfig{
			Type:              "passwd",
			CredentialBackend: "passwd",
			KeyBackend:        "keys",
		},
		MsgStore: DomainMsgStoreConfig{
			Type:     "maildir",
			BasePath: "users",
		},
	}
	defaultsMap, err := toTOMLMap(defaults)
	if err != nil {
		t.Fatal(err)
	}

	sysMap, err := loadTOMLMap(sysConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	domMap, err := loadTOMLMap(domConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	var cfg DomainConfig
	if err := mergeConfigLayers(&cfg, defaultsMap, sysMap, domMap); err != nil {
		t.Fatal(err)
	}

	// Auth from programmatic defaults
	if cfg.Auth.Type != "passwd" {
		t.Errorf("Auth.Type = %q, want passwd", cfg.Auth.Type)
	}
	// RecipientRejection from system config
	if cfg.RecipientRejection != "data" {
		t.Errorf("RecipientRejection = %q, want data", cfg.RecipientRejection)
	}
	// Limits from per-domain (overrides system)
	if cfg.Limits.MaxSendsPerHour != 25 {
		t.Errorf("Limits.MaxSendsPerHour = %d, want 25", cfg.Limits.MaxSendsPerHour)
	}
	// MsgStore from programmatic defaults
	if cfg.MsgStore.Type != "maildir" {
		t.Errorf("MsgStore.Type = %q, want maildir", cfg.MsgStore.Type)
	}
}
