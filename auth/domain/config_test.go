package domain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomainConfig_GidTOML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	content := `gid = 2001

[auth]
type = "passwd"

[msgstore]
type = "maildir"
base_path = "users"
`
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadDomainConfig(configPath)
	if err != nil {
		t.Fatalf("LoadDomainConfig: %v", err)
	}
	if cfg.Gid != 2001 {
		t.Errorf("expected Gid 2001, got %d", cfg.Gid)
	}
}

func TestMergeConfig_Gid(t *testing.T) {
	base := DomainConfig{Gid: 1000}
	override := DomainConfig{Gid: 2001}

	result := mergeConfig(base, override)
	if result.Gid != 2001 {
		t.Errorf("expected merged Gid 2001, got %d", result.Gid)
	}

	// Zero override should not overwrite base
	result = mergeConfig(base, DomainConfig{})
	if result.Gid != 1000 {
		t.Errorf("expected base Gid 1000 retained, got %d", result.Gid)
	}
}
