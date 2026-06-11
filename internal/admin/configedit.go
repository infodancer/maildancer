package admin

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// valueKind describes how a config value is validated and TOML-encoded.
type valueKind int

const (
	kindString valueKind = iota
	kindInt
	kindEnum
	kindPath
	kindIP
)

// configField maps an admin-visible key to its location in the per-domain
// config.toml and its value handling.
type configField struct {
	section string // "" = top-level table
	key     string
	kind    valueKind
	enum    []string // valid values for kindEnum
}

// domainConfigFields is the curated set of per-domain config keys editable
// through SetDomainConfig. Deliberately excluded: forwards (owned by the
// forward-editing API in auth/domain), gid (owned by allocation), and
// auth.options/msgstore.options (free-form tables, not key=value).
var domainConfigFields = map[string]configField{
	"auth.type":                 {section: "auth", key: "type", kind: kindString},
	"auth.credential_backend":   {section: "auth", key: "credential_backend", kind: kindPath},
	"auth.key_backend":          {section: "auth", key: "key_backend", kind: kindPath},
	"msgstore.type":             {section: "msgstore", key: "type", kind: kindString},
	"msgstore.base_path":        {section: "msgstore", key: "base_path", kind: kindPath},
	"dkim.selector":             {section: "dkim", key: "selector", kind: kindString},
	"dkim.private_key":          {section: "dkim", key: "private_key", kind: kindPath},
	"outbound.strategy":         {section: "outbound", key: "strategy", kind: kindEnum, enum: []string{"direct", "smarthost"}},
	"outbound.smarthost":        {section: "outbound", key: "smarthost", kind: kindString},
	"outbound.smarthost_user":   {section: "outbound", key: "smarthost_user", kind: kindString},
	"outbound.password_file":    {section: "outbound", key: "password_file", kind: kindPath},
	"limits.max_sends_per_hour": {section: "limits", key: "max_sends_per_hour", kind: kindInt},
	"dns.hostname":              {section: "dns", key: "hostname", kind: kindString},
	"dns.public_ip":             {section: "dns", key: "public_ip", kind: kindIP},
	"max_message_size":          {section: "", key: "max_message_size", kind: kindInt},
	"recipient_rejection":       {section: "", key: "recipient_rejection", kind: kindEnum, enum: []string{"rcpt", "data"}},
}

// ErrUnknownConfigKey is returned for keys outside the curated set.
var ErrUnknownConfigKey = fmt.Errorf("unknown config key (see DomainConfigKeys)")

// DomainConfigKeys returns the editable per-domain config keys, sorted.
func DomainConfigKeys() []string {
	out := make([]string, 0, len(domainConfigFields))
	for k := range domainConfigFields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SetDomainConfig sets (or, with an empty value, removes) one whitelisted key
// in the domain's config.toml, preserving all other file content including
// comments and unmanaged sections. Values are validated per key: integers
// must parse non-negative, enums must match their allowed set, and paths must
// not traverse upward.
func (p Paths) SetDomainConfig(domain, key, value string) error {
	if !ValidDomainName(domain) {
		return ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return ErrDomainNotFound
	}
	field, ok := domainConfigFields[key]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownConfigKey, key)
	}

	rawValue, err := encodeConfigValue(field, value)
	if err != nil {
		return fmt.Errorf("invalid value for %s: %w", key, err)
	}

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return err
	}
	defer unlock()

	configPath := filepath.Join(p.Config, domain, "config.toml")
	content, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}

	patched := PatchSectionValue(content, field.section, field.key, rawValue)
	return writeFileAtomic(configPath, patched, 0o640)
}

// GetDomainConfigValue returns the current raw TOML value for a whitelisted
// key, or "" if unset.
func (p Paths) GetDomainConfigValue(domain, key string) (string, error) {
	if !ValidDomainName(domain) {
		return "", ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return "", ErrDomainNotFound
	}
	field, ok := domainConfigFields[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownConfigKey, key)
	}

	content, err := os.ReadFile(filepath.Join(p.Config, domain, "config.toml"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read config: %w", err)
	}
	return readSectionValue(content, field.section, field.key), nil
}

// encodeConfigValue validates value for the field and returns its TOML
// encoding. An empty value means "remove the key" and passes through.
func encodeConfigValue(field configField, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	switch field.kind {
	case kindInt:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return "", fmt.Errorf("expected a non-negative integer, got %q", value)
		}
		return strconv.FormatInt(n, 10), nil
	case kindEnum:
		for _, allowed := range field.enum {
			if value == allowed {
				return QuoteString(value), nil
			}
		}
		return "", fmt.Errorf("expected one of %v, got %q", field.enum, value)
	case kindPath:
		if !validRelativeOrAbsPath(value) {
			return "", fmt.Errorf("path %q must not traverse upward", value)
		}
		return QuoteString(value), nil
	case kindIP:
		if net.ParseIP(value) == nil {
			return "", fmt.Errorf("expected an IP address, got %q", value)
		}
		return QuoteString(value), nil
	default:
		return QuoteString(value), nil
	}
}

// validRelativeOrAbsPath rejects paths with upward traversal components.
func validRelativeOrAbsPath(p string) bool {
	clean := filepath.Clean(p)
	return clean != ".." && !startsWithDotDot(clean)
}

func startsWithDotDot(p string) bool {
	return len(p) >= 3 && p[:3] == ".."+string(filepath.Separator)
}

// readSectionValue returns the raw value of key in [section] (or the
// top-level table when section is empty), or "" when absent.
func readSectionValue(content []byte, section, key string) string {
	lines := strings.Split(string(content), "\n")
	start, end := 0, len(lines)
	if section != "" {
		header := "[" + section + "]"
		start = -1
		for i, line := range lines {
			if strings.TrimSpace(line) == header {
				start = i + 1
				break
			}
		}
		if start < 0 {
			return ""
		}
		end = len(lines)
		for i := start; i < len(lines); i++ {
			if isTOMLSectionHeader(strings.TrimSpace(lines[i])) {
				end = i
				break
			}
		}
	} else {
		for i, line := range lines {
			if isTOMLSectionHeader(strings.TrimSpace(line)) {
				end = i
				break
			}
		}
	}
	for i := start; i < end; i++ {
		if matchesTOMLKey(lines[i], key) {
			t := strings.TrimSpace(lines[i])
			if idx := strings.IndexByte(t, '='); idx >= 0 {
				return strings.TrimSpace(t[idx+1:])
			}
		}
	}
	return ""
}

// writeFileAtomic writes data via temp file + fsync + rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
