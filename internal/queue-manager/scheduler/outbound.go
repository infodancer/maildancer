package scheduler

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// warnInsecurePerms logs a warning if a sensitive file is group-writable or
// world-readable. Best-effort: errors from Stat are silently ignored.
func warnInsecurePerms(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := fi.Mode().Perm()
	if perm&0o027 != 0 {
		slog.Warn("sensitive file has overly permissive permissions",
			"path", path,
			"mode", fmt.Sprintf("%04o", perm),
			"recommended", "0600 or 0640")
	}
}

// OutboundConfig holds per-sender-domain delivery transport settings.
type OutboundConfig struct {
	Strategy      string `toml:"strategy"`       // "direct" | "smarthost"; default "direct"
	Smarthost     string `toml:"smarthost"`      // host:port
	SmarthostUser string `toml:"smarthost_user"` // SMTP AUTH username
	PasswordFile  string `toml:"password_file"`  // relative to domain dir or absolute
	password      string // resolved password; not from TOML
}

// domainFileConfig is a minimal struct for parsing [outbound] from domain config files.
type domainFileConfig struct {
	Outbound OutboundConfig `toml:"outbound"`
}

// senderDomainFromBodyPath extracts the sender FQDN from a body file path.
// Body path format: {queueDir}/msg/{tld}/{domain}/{msgid}
// Returns domain.tld (e.g., "example.com").
func senderDomainFromBodyPath(queueDir, bodyPath string) string {
	msgDir := filepath.Join(queueDir, "msg") + string(filepath.Separator)
	rel := strings.TrimPrefix(bodyPath, msgDir)
	if rel == bodyPath {
		return ""
	}
	parts := strings.SplitN(rel, string(filepath.Separator), 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1] + "." + parts[0]
}

// loadOutboundConfig reads outbound transport config for a sender domain.
// It reads the system default from {basePath}/config.toml, then overrides
// with {basePath}/{senderDomain}/config.toml. Returns zero-value config
// if neither file has an [outbound] section.
func loadOutboundConfig(basePath, senderDomain string) (OutboundConfig, error) {
	sysCfg, err := readOutboundFromFile(filepath.Join(basePath, "config.toml"))
	if err != nil {
		return OutboundConfig{}, fmt.Errorf("reading system outbound config: %w", err)
	}

	domCfg, err := readOutboundFromFile(filepath.Join(basePath, senderDomain, "config.toml"))
	if err != nil {
		return OutboundConfig{}, fmt.Errorf("reading domain outbound config for %s: %w", senderDomain, err)
	}

	// Merge: domain fields override system defaults.
	merged := sysCfg
	if domCfg.Strategy != "" {
		merged.Strategy = domCfg.Strategy
	}
	if domCfg.Smarthost != "" {
		merged.Smarthost = domCfg.Smarthost
	}
	if domCfg.SmarthostUser != "" {
		merged.SmarthostUser = domCfg.SmarthostUser
	}
	if domCfg.PasswordFile != "" {
		merged.PasswordFile = domCfg.PasswordFile
	}

	return merged, nil
}

// readOutboundFromFile reads the [outbound] section from a TOML file.
// Returns zero-value OutboundConfig if the file does not exist.
func readOutboundFromFile(path string) (OutboundConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return OutboundConfig{}, nil
		}
		return OutboundConfig{}, err
	}
	var fc domainFileConfig
	if err := toml.Unmarshal(data, &fc); err != nil {
		return OutboundConfig{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return fc.Outbound, nil
}

// readPasswordFile reads and trims the smarthost password from a file.
// If passwordFile is relative, it is resolved from {basePath}/{senderDomain}/.
// Returns empty string with no error if PasswordFile is empty.
func readPasswordFile(basePath, senderDomain string, cfg OutboundConfig) (string, error) {
	if cfg.PasswordFile == "" {
		return "", nil
	}
	path := cfg.PasswordFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(basePath, senderDomain, path)
	}
	warnInsecurePerms(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading password file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
