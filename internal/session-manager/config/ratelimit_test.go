package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeConfig writes a config file and loads it.
func loadFromString(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoad_RateLimitAndPeerFilter(t *testing.T) {
	cfg := loadFromString(t, `
[server]
domains_path = "/srv/domains"

[session-manager]
socket = "/run/sm.sock"
mail_session_cmd = "/usr/bin/mail-session"

[session-manager.redis]
url = "redis://redis:6379/1"

[session-manager.ratelimit]
enabled = true
max_failures_per_ip_user = 3
max_failures_per_ip = 12
window = "10m"
lockout = "30m"

[session-manager.peerfilter]
enabled = true
allowlist = ["127.0.0.0/8", "10.0.0.0/8"]
ban_ttl = "12h"
ban_ttl_repeat = "72h"
accept_tarpit = "20s"
abuse_window = "45m"

[session-manager.peerfilter.abuse_thresholds]
early_talker = 4
data_abort = 6
`)

	if cfg.Redis.URL != "redis://redis:6379/1" {
		t.Errorf("redis url = %q", cfg.Redis.URL)
	}

	if !cfg.RateLimit.IsEnabled() {
		t.Error("ratelimit not enabled")
	}
	if cfg.RateLimit.MaxFailuresPerIPUser != 3 || cfg.RateLimit.MaxFailuresPerIP != 12 {
		t.Errorf("thresholds = %d/%d, want 3/12",
			cfg.RateLimit.MaxFailuresPerIPUser, cfg.RateLimit.MaxFailuresPerIP)
	}
	if cfg.RateLimit.Window != 10*time.Minute || cfg.RateLimit.Lockout != 30*time.Minute {
		t.Errorf("durations = %v/%v, want 10m/30m", cfg.RateLimit.Window, cfg.RateLimit.Lockout)
	}

	if !cfg.PeerFilter.IsEnabled() {
		t.Error("peerfilter not enabled")
	}
	if len(cfg.PeerFilter.Allowlist) != 2 {
		t.Errorf("allowlist = %v", cfg.PeerFilter.Allowlist)
	}
	if cfg.PeerFilter.BanTTL != 12*time.Hour || cfg.PeerFilter.BanTTLRepeat != 72*time.Hour {
		t.Errorf("ban TTLs = %v/%v, want 12h/72h",
			cfg.PeerFilter.BanTTL, cfg.PeerFilter.BanTTLRepeat)
	}
	if cfg.PeerFilter.AcceptTarpit != 20*time.Second {
		t.Errorf("accept_tarpit = %v, want 20s", cfg.PeerFilter.AcceptTarpit)
	}
	if cfg.PeerFilter.AbuseWindow != 45*time.Minute {
		t.Errorf("abuse_window = %v, want 45m", cfg.PeerFilter.AbuseWindow)
	}
	if got := cfg.PeerFilter.AbuseThresholds["early_talker"]; got != 4 {
		t.Errorf("early_talker threshold = %d, want 4", got)
	}
}

// TestLoad_DefaultsWhenSectionsAbsent covers the upgrade path: an existing
// config file with none of the new sections must load with both features
// enabled -- secure by default -- and with no zero-valued durations that would
// mean "expire immediately".
func TestLoad_DefaultsWhenSectionsAbsent(t *testing.T) {
	cfg := loadFromString(t, `
[server]
domains_path = "/srv/domains"

[session-manager]
socket = "/run/sm.sock"
mail_session_cmd = "/usr/bin/mail-session"
`)

	if cfg.Redis.URL != "" {
		t.Errorf("redis url = %q, want empty", cfg.Redis.URL)
	}
	// Secure by default. Neither actually enforces anything without Redis --
	// the filter is off entirely and the limiter falls back to per-process
	// counters -- so defaulting on cannot surprise a deployment that has no
	// Redis configured, while a deployment that does gets protection without
	// having to opt in twice.
	if !cfg.RateLimit.IsEnabled() {
		t.Error("ratelimit disabled with no config section; must default on")
	}
	if !cfg.PeerFilter.IsEnabled() {
		t.Error("peerfilter disabled with no config section; must default on")
	}

	// Durations still normalize, so enabling the feature later needs no
	// further edits and cannot inherit a zero TTL.
	if cfg.RateLimit.Window <= 0 || cfg.RateLimit.Lockout <= 0 {
		t.Errorf("ratelimit durations not defaulted: %+v", cfg.RateLimit)
	}
	if cfg.PeerFilter.BanTTL <= 0 || cfg.PeerFilter.BanTTLRepeat <= 0 {
		t.Errorf("peerfilter TTLs not defaulted: %+v", cfg.PeerFilter)
	}
	if cfg.RateLimit.MaxFailuresPerIPUser <= 0 || cfg.RateLimit.MaxFailuresPerIP <= 0 {
		t.Errorf("ratelimit thresholds not defaulted: %+v", cfg.RateLimit)
	}
}

func TestLoad_RejectsBadDurations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[session-manager]
socket = "/run/sm.sock"

[session-manager.peerfilter]
enabled = true
ban_ttl = "forever"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("invalid ban_ttl accepted")
	}
}

func TestRedisConfig_Client(t *testing.T) {
	// No URL means the feature is off, not an error.
	client, err := RedisConfig{}.Client()
	if err != nil {
		t.Fatalf("Client with no URL: %v", err)
	}
	if client != nil {
		t.Error("Client returned a client for an empty URL")
	}

	client, err = RedisConfig{URL: "redis://localhost:6379/2", Password: "secret"}.Client()
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if client == nil {
		t.Fatal("Client returned nil for a valid URL")
	}
	defer func() { _ = client.Close() }()
	if got := client.Options().Password; got != "secret" {
		t.Errorf("password = %q, want the configured value", got)
	}

	if _, err := (RedisConfig{URL: "not a url"}).Client(); err == nil {
		t.Error("invalid redis URL accepted")
	}
}

func TestRedisConfig_PasswordFromEnv(t *testing.T) {
	t.Setenv("REDIS_PASSWORD", "from-env")
	cfg := loadFromString(t, `
[session-manager]
socket = "/run/sm.sock"

[session-manager.redis]
url = "redis://redis:6379/1"
`)
	if cfg.Redis.Password != "from-env" {
		t.Errorf("password = %q, want the environment value", cfg.Redis.Password)
	}
}

// TestRedisConfig_FilePasswordWinsOverEnv keeps the environment from silently
// overriding an explicit configuration choice.
func TestRedisConfig_FilePasswordWinsOverEnv(t *testing.T) {
	t.Setenv("REDIS_PASSWORD", "from-env")
	cfg := loadFromString(t, `
[session-manager]
socket = "/run/sm.sock"

[session-manager.redis]
url = "redis://redis:6379/1"
password = "from-file"
`)
	if cfg.Redis.Password != "from-file" {
		t.Errorf("password = %q, want the file value", cfg.Redis.Password)
	}
}

func TestRateLimitConfig_DomainConfig(t *testing.T) {
	c := RateLimitConfig{
		MaxFailuresPerIPUser: 4,
		MaxFailuresPerIP:     9,
		Window:               time.Minute,
		Lockout:              time.Hour,
	}
	dc := c.DomainConfig()
	if dc.MaxFailuresPerIPUser != 4 || dc.MaxFailuresPerIP != 9 ||
		dc.Window != time.Minute || dc.Lockout != time.Hour {
		t.Errorf("DomainConfig lost values: %+v", dc)
	}
}

func TestLoad_AuthFailDelay(t *testing.T) {
	cfg := loadFromString(t, `
[session-manager]
socket = "/run/sm.sock"
auth_fail_delay = "2s"
`)
	if cfg.AuthFailDelay != 2*time.Second {
		t.Errorf("auth_fail_delay = %v, want 2s", cfg.AuthFailDelay)
	}
}

// TestLoad_AuthFailDelayDefault pins the 5s decision: it must apply without
// being configured, since an absent delay would leave the enumeration oracle
// open by default.
func TestLoad_AuthFailDelayDefault(t *testing.T) {
	cfg := loadFromString(t, `
[session-manager]
socket = "/run/sm.sock"
`)
	if cfg.AuthFailDelay != DefaultAuthFailDelay {
		t.Errorf("auth_fail_delay = %v, want the %v default", cfg.AuthFailDelay, DefaultAuthFailDelay)
	}
}

// TestLoad_AuthFailDelayExplicitZero keeps an operator able to turn the delay
// off. A zero must survive rather than being read as "unset" and defaulted.
func TestLoad_AuthFailDelayExplicitZero(t *testing.T) {
	cfg := loadFromString(t, `
[session-manager]
socket = "/run/sm.sock"
auth_fail_delay = "0s"
`)
	if cfg.AuthFailDelay != 0 {
		t.Errorf("auth_fail_delay = %v, want 0 when explicitly configured as 0s", cfg.AuthFailDelay)
	}
}

func TestLoad_AuthFailDelayRejectsBadDuration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[session-manager]
socket = "/run/sm.sock"
auth_fail_delay = "eventually"
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("invalid auth_fail_delay accepted")
	}
}
