package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Defaults()

	if cfg.WebAdmin.ListenAddress != "localhost:8080" {
		t.Errorf("expected default listen address localhost:8080, got %s", cfg.WebAdmin.ListenAddress)
	}
	if cfg.WebAdmin.LogLevel != "info" {
		t.Errorf("expected default log level info, got %s", cfg.WebAdmin.LogLevel)
	}
	if cfg.WebAdmin.Session.TimeoutMinutes != 30 {
		t.Errorf("expected default session timeout 30, got %d", cfg.WebAdmin.Session.TimeoutMinutes)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid minimal config",
			cfg: Config{
				WebAdmin: WebAdminConfig{
					DomainsPath: "/etc/mail/domains",
					Auth:        AuthConfig{PasswdFile: "/etc/mail/admin-passwd"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing domains_path",
			cfg: Config{
				WebAdmin: WebAdminConfig{
					Auth: AuthConfig{PasswdFile: "/etc/mail/admin-passwd"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing passwd_file",
			cfg: Config{
				WebAdmin: WebAdminConfig{
					DomainsPath: "/etc/mail/domains",
				},
			},
			wantErr: true,
		},
		{
			name: "tls cert without key",
			cfg: Config{
				WebAdmin: WebAdminConfig{
					DomainsPath: "/etc/mail/domains",
					Auth:        AuthConfig{PasswdFile: "/etc/mail/admin-passwd"},
					TLS:         TLSConfig{CertFile: "/etc/ssl/cert.pem"},
				},
			},
			wantErr: true,
		},
		{
			name: "tls key without cert",
			cfg: Config{
				WebAdmin: WebAdminConfig{
					DomainsPath: "/etc/mail/domains",
					Auth:        AuthConfig{PasswdFile: "/etc/mail/admin-passwd"},
					TLS:         TLSConfig{KeyFile: "/etc/ssl/key.pem"},
				},
			},
			wantErr: true,
		},
		{
			name: "valid with tls",
			cfg: Config{
				WebAdmin: WebAdminConfig{
					DomainsPath: "/etc/mail/domains",
					Auth:        AuthConfig{PasswdFile: "/etc/mail/admin-passwd"},
					TLS: TLSConfig{
						CertFile: "/etc/ssl/cert.pem",
						KeyFile:  "/etc/ssl/key.pem",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	content := `
[webadmin]
listen_address = "0.0.0.0:9090"
domains_path = "/var/mail/domains"
log_level = "debug"

[webadmin.auth]
passwd_file = "/etc/mail/admin-passwd"

[webadmin.session]
timeout_minutes = 60

[webadmin.tls]
cert_file = "/etc/ssl/cert.pem"
key_file = "/etc/ssl/key.pem"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.WebAdmin.ListenAddress != "0.0.0.0:9090" {
		t.Errorf("expected listen address 0.0.0.0:9090, got %s", cfg.WebAdmin.ListenAddress)
	}
	if cfg.WebAdmin.DomainsPath != "/var/mail/domains" {
		t.Errorf("expected domains path /var/mail/domains, got %s", cfg.WebAdmin.DomainsPath)
	}
	if cfg.WebAdmin.LogLevel != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.WebAdmin.LogLevel)
	}
	if cfg.WebAdmin.Auth.PasswdFile != "/etc/mail/admin-passwd" {
		t.Errorf("expected passwd file /etc/mail/admin-passwd, got %s", cfg.WebAdmin.Auth.PasswdFile)
	}
	if cfg.WebAdmin.Session.TimeoutMinutes != 60 {
		t.Errorf("expected session timeout 60, got %d", cfg.WebAdmin.Session.TimeoutMinutes)
	}
	if cfg.WebAdmin.TLS.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("expected TLS cert file, got %s", cfg.WebAdmin.TLS.CertFile)
	}
}

func TestLoadNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.toml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestTLSEnabled(t *testing.T) {
	cfg := &WebAdminConfig{}
	if cfg.TLSEnabled() {
		t.Error("expected TLS disabled with empty config")
	}

	cfg.TLS.CertFile = "/cert.pem"
	cfg.TLS.KeyFile = "/key.pem"
	if !cfg.TLSEnabled() {
		t.Error("expected TLS enabled with cert and key")
	}
}
