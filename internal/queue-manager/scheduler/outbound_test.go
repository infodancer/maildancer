package scheduler

import (
	"os"
	"path/filepath"
	"testing"
)

// --- senderDomainFromBodyPath ---

func TestSenderDomainFromBodyPath(t *testing.T) {
	cases := []struct {
		name     string
		queueDir string
		bodyPath string
		want     string
	}{
		{
			name:     "single TLD",
			queueDir: "/var/spool/queue",
			bodyPath: "/var/spool/queue/msg/com/example/abc123",
			want:     "example.com",
		},
		{
			name:     "multi-level TLD",
			queueDir: "/var/spool/queue",
			bodyPath: "/var/spool/queue/msg/uk/example.co/abc123",
			want:     "example.co.uk",
		},
		{
			name:     "different domain",
			queueDir: "/tmp/q",
			bodyPath: "/tmp/q/msg/net/infodancer/msgid999",
			want:     "infodancer.net",
		},
		{
			name:     "path mismatch",
			queueDir: "/var/spool/queue",
			bodyPath: "/other/path/msg/com/example/abc123",
			want:     "",
		},
		{
			name:     "too few parts",
			queueDir: "/var/spool/queue",
			bodyPath: "/var/spool/queue/msg/com",
			want:     "",
		},
		{
			name:     "empty body path",
			queueDir: "/var/spool/queue",
			bodyPath: "",
			want:     "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := senderDomainFromBodyPath(c.queueDir, c.bodyPath)
			if got != c.want {
				t.Errorf("senderDomainFromBodyPath(%q, %q) = %q, want %q",
					c.queueDir, c.bodyPath, got, c.want)
			}
		})
	}
}

// --- loadOutboundConfig ---

func TestLoadOutboundConfig_SystemDefaultOnly(t *testing.T) {
	dir := t.TempDir()
	content := `
[outbound]
strategy = "smarthost"
smarthost = "smtp.relay.example.com:587"
smarthost_user = "relay-user"
password_file = "relay-pass"
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOutboundConfig(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost", cfg.Strategy)
	}
	if cfg.Smarthost != "smtp.relay.example.com:587" {
		t.Errorf("Smarthost = %q", cfg.Smarthost)
	}
	if cfg.SmarthostUser != "relay-user" {
		t.Errorf("SmarthostUser = %q", cfg.SmarthostUser)
	}
	if cfg.PasswordFile != "relay-pass" {
		t.Errorf("PasswordFile = %q", cfg.PasswordFile)
	}
}

func TestLoadOutboundConfig_DomainOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(`
[outbound]
strategy = "direct"
`), 0600); err != nil {
		t.Fatal(err)
	}

	domDir := filepath.Join(dir, "otherdomain.com")
	if err := os.MkdirAll(domDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domDir, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "ses.amazonaws.com:587"
smarthost_user = "AKIA123"
password_file = "ses-pass"
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOutboundConfig(dir, "otherdomain.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost", cfg.Strategy)
	}
	if cfg.Smarthost != "ses.amazonaws.com:587" {
		t.Errorf("Smarthost = %q", cfg.Smarthost)
	}
	if cfg.SmarthostUser != "AKIA123" {
		t.Errorf("SmarthostUser = %q", cfg.SmarthostUser)
	}
	if cfg.PasswordFile != "ses-pass" {
		t.Errorf("PasswordFile = %q", cfg.PasswordFile)
	}
}

func TestLoadOutboundConfig_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadOutboundConfig(dir, "missing.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Strategy != "" {
		t.Errorf("Strategy = %q, want empty", cfg.Strategy)
	}
	if cfg.Smarthost != "" {
		t.Errorf("Smarthost = %q, want empty", cfg.Smarthost)
	}
}

func TestLoadOutboundConfig_MergePartialOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "default-relay:587"
smarthost_user = "default-user"
password_file = "default-pass"
`), 0600); err != nil {
		t.Fatal(err)
	}

	domDir := filepath.Join(dir, "custom.com")
	if err := os.MkdirAll(domDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domDir, "config.toml"), []byte(`
[outbound]
smarthost = "custom-relay:465"
smarthost_user = "custom-user"
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOutboundConfig(dir, "custom.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Strategy != "smarthost" {
		t.Errorf("Strategy = %q, want smarthost (from system default)", cfg.Strategy)
	}
	if cfg.Smarthost != "custom-relay:465" {
		t.Errorf("Smarthost = %q, want custom-relay:465", cfg.Smarthost)
	}
	if cfg.SmarthostUser != "custom-user" {
		t.Errorf("SmarthostUser = %q, want custom-user", cfg.SmarthostUser)
	}
	if cfg.PasswordFile != "default-pass" {
		t.Errorf("PasswordFile = %q, want default-pass (from system default)", cfg.PasswordFile)
	}
}

// --- readPasswordFile ---

func TestReadPasswordFile_RelativePath(t *testing.T) {
	dir := t.TempDir()
	domDir := filepath.Join(dir, "example.com")
	if err := os.MkdirAll(domDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domDir, "ses-pass"), []byte("  s3cr3t\n  "), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := OutboundConfig{PasswordFile: "ses-pass"}
	got, err := readPasswordFile(dir, "example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cr3t" {
		t.Errorf("password = %q, want s3cr3t", got)
	}
}

func TestReadPasswordFile_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	passFile := filepath.Join(dir, "absolute-pass")
	if err := os.WriteFile(passFile, []byte("abs-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := OutboundConfig{PasswordFile: passFile}
	got, err := readPasswordFile("/some/other/base", "example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abs-secret" {
		t.Errorf("password = %q, want abs-secret", got)
	}
}

func TestReadPasswordFile_MissingFile(t *testing.T) {
	cfg := OutboundConfig{PasswordFile: "nonexistent"}
	_, err := readPasswordFile("/tmp", "example.com", cfg)
	if err == nil {
		t.Error("expected error for missing password file")
	}
}

func TestReadPasswordFile_EmptyPasswordFile(t *testing.T) {
	cfg := OutboundConfig{}
	got, err := readPasswordFile("/tmp", "example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("password = %q, want empty", got)
	}
}

// --- smarthost_user_file (symmetric with password_file) ---

func TestLoadOutboundConfig_SmarthostUserFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "smtp.postmarkapp.com:587"
smarthost_user_file = "postmark-token"
password_file = "postmark-token"
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOutboundConfig(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SmarthostUserFile != "postmark-token" {
		t.Errorf("SmarthostUserFile = %q, want postmark-token", cfg.SmarthostUserFile)
	}
	if cfg.PasswordFile != "postmark-token" {
		t.Errorf("PasswordFile = %q, want postmark-token", cfg.PasswordFile)
	}
}

func TestLoadOutboundConfig_SmarthostUserFileDomainOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(`
[outbound]
strategy = "smarthost"
smarthost = "default-relay:587"
smarthost_user_file = "default-token"
`), 0600); err != nil {
		t.Fatal(err)
	}
	domDir := filepath.Join(dir, "custom.com")
	if err := os.MkdirAll(domDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domDir, "config.toml"), []byte(`
[outbound]
smarthost_user_file = "custom-token"
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadOutboundConfig(dir, "custom.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SmarthostUserFile != "custom-token" {
		t.Errorf("SmarthostUserFile = %q, want custom-token (domain override)", cfg.SmarthostUserFile)
	}
}

func TestReadSmarthostUserFile_RelativePath(t *testing.T) {
	dir := t.TempDir()
	domDir := filepath.Join(dir, "example.com")
	if err := os.MkdirAll(domDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(domDir, "postmark-token"), []byte("  abc-123-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := OutboundConfig{SmarthostUserFile: "postmark-token"}
	got, err := readSmarthostUserFile(dir, "example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc-123-token" {
		t.Errorf("smarthost user = %q, want abc-123-token", got)
	}
}

func TestReadSmarthostUserFile_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	userFile := filepath.Join(dir, "absolute-token")
	if err := os.WriteFile(userFile, []byte("abs-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := OutboundConfig{SmarthostUserFile: userFile}
	got, err := readSmarthostUserFile("/some/other/base", "example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abs-token" {
		t.Errorf("smarthost user = %q, want abs-token", got)
	}
}

func TestReadSmarthostUserFile_Empty(t *testing.T) {
	cfg := OutboundConfig{}
	got, err := readSmarthostUserFile("/tmp", "example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("smarthost user = %q, want empty", got)
	}
}

func TestReadSmarthostUserFile_MissingFile(t *testing.T) {
	cfg := OutboundConfig{SmarthostUserFile: "nonexistent"}
	_, err := readSmarthostUserFile("/tmp", "example.com", cfg)
	if err == nil {
		t.Error("expected error for missing smarthost user file")
	}
}
