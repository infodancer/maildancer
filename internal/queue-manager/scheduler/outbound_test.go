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

// TestLoadOutboundConfig tables the global/per-domain merge scenarios for
// loadOutboundConfig: a global config.toml, an optional per-domain override
// under <dir>/<domain>/config.toml, and the four fields the merge produces.
func TestLoadOutboundConfig(t *testing.T) {
	cases := []struct {
		name          string
		globalTOML    string
		domain        string
		domainTOML    string // empty = no per-domain file written
		wantStrategy  string
		wantSmarthost string
		wantUser      string
		wantPassFile  string
	}{
		{
			name: "system default only",
			globalTOML: `
[outbound]
strategy = "smarthost"
smarthost = "smtp.relay.example.com:587"
smarthost_user = "relay-user"
password_file = "relay-pass"
`,
			domain:        "example.com",
			wantStrategy:  "smarthost",
			wantSmarthost: "smtp.relay.example.com:587",
			wantUser:      "relay-user",
			wantPassFile:  "relay-pass",
		},
		{
			name: "domain override replaces the default entirely",
			globalTOML: `
[outbound]
strategy = "direct"
`,
			domain: "otherdomain.com",
			domainTOML: `
[outbound]
strategy = "smarthost"
smarthost = "ses.amazonaws.com:587"
smarthost_user = "AKIA123"
password_file = "ses-pass"
`,
			wantStrategy:  "smarthost",
			wantSmarthost: "ses.amazonaws.com:587",
			wantUser:      "AKIA123",
			wantPassFile:  "ses-pass",
		},
		{
			name:         "missing files",
			domain:       "missing.com",
			wantStrategy: "",
		},
		{
			name: "merge keeps default fields the override omits",
			globalTOML: `
[outbound]
strategy = "smarthost"
smarthost = "default-relay:587"
smarthost_user = "default-user"
password_file = "default-pass"
`,
			domain: "custom.com",
			domainTOML: `
[outbound]
smarthost = "custom-relay:465"
smarthost_user = "custom-user"
`,
			wantStrategy:  "smarthost", // from system default
			wantSmarthost: "custom-relay:465",
			wantUser:      "custom-user",
			wantPassFile:  "default-pass", // from system default
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.globalTOML != "" {
				if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(tc.globalTOML), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.domainTOML != "" {
				domDir := filepath.Join(dir, tc.domain)
				if err := os.MkdirAll(domDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(domDir, "config.toml"), []byte(tc.domainTOML), 0600); err != nil {
					t.Fatal(err)
				}
			}

			cfg, err := loadOutboundConfig(dir, tc.domain)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Strategy != tc.wantStrategy {
				t.Errorf("Strategy = %q, want %q", cfg.Strategy, tc.wantStrategy)
			}
			if cfg.Smarthost != tc.wantSmarthost {
				t.Errorf("Smarthost = %q, want %q", cfg.Smarthost, tc.wantSmarthost)
			}
			if cfg.SmarthostUser != tc.wantUser {
				t.Errorf("SmarthostUser = %q, want %q", cfg.SmarthostUser, tc.wantUser)
			}
			if cfg.PasswordFile != tc.wantPassFile {
				t.Errorf("PasswordFile = %q, want %q", cfg.PasswordFile, tc.wantPassFile)
			}
		})
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
