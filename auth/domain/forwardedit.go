package domain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ErrMultiTargetForward indicates a forward was configured with more than one
// target. Forwarding is strictly 1:1 -- per-user fan-out belongs in sieve and
// multi-recipient distribution belongs in a mailing-list manager, not in the
// forwards chain. This mirrors the delivery-time policy enforced in
// mail-session's delivery pipeline.
var ErrMultiTargetForward = errors.New("forwarding is 1:1: exactly one target address is allowed")

// ErrInvalidForwardTarget indicates the target is not a single valid
// localpart@domain address.
var ErrInvalidForwardTarget = errors.New("invalid forward target: expected a single localpart@domain address")

// ErrDomainNotFound indicates the domain has no directory under the domains path.
var ErrDomainNotFound = errors.New("domain not found")

// ValidateForwardTarget enforces the 1:1 forwarding policy and a basic address
// shape. It returns the normalized (trimmed, lowercased) single target, or an
// error: ErrMultiTargetForward if the input names more than one address,
// ErrInvalidForwardTarget if it is empty or not a single localpart@domain.
//
// A forward target must be a fully-qualified address because the delivery path
// re-routes it through normal recipient classification (local deliver vs.
// outbound enqueue), which needs the domain.
func ValidateForwardTarget(target string) (string, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", ErrInvalidForwardTarget
	}
	// Reject any multi-target spelling -- comma-separated or whitespace-separated.
	if strings.Contains(t, ",") || len(strings.Fields(t)) != 1 {
		return "", ErrMultiTargetForward
	}
	t = strings.ToLower(t)
	at := strings.IndexByte(t, '@')
	if at <= 0 || at == len(t)-1 || strings.Count(t, "@") != 1 {
		return "", ErrInvalidForwardTarget
	}
	return t, nil
}

// domainConfigPath returns the per-domain config.toml path. This is the file
// whose [forwards] table the forwarding chain actually reads: a domain's own
// config.toml takes ownership of forwarding (see loadDomain). Forwards written
// only to the central domains.toml do not take effect unless the per-domain
// config.toml also declares [forwards].
func domainConfigPath(domainsPath, domain string) string {
	return filepath.Join(domainsPath, strings.ToLower(strings.TrimSpace(domain)), "config.toml")
}

// loadOrEmptyDomainConfig loads a per-domain config.toml, returning an empty
// config (not an error) when the file does not exist.
func loadOrEmptyDomainConfig(path string) (*DomainConfig, error) {
	cfg, err := LoadDomainConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &DomainConfig{}, nil
		}
		return nil, err
	}
	return cfg, nil
}

// ListDomainForwards returns the forwards configured in the domain's
// config.toml [forwards] table (localpart -> single target). The special key
// "*" is the catchall. Returns an empty map when none are configured.
func ListDomainForwards(domainsPath, domain string) (map[string]string, error) {
	cfg, err := loadOrEmptyDomainConfig(domainConfigPath(domainsPath, domain))
	if err != nil {
		return nil, err
	}
	if cfg.Forwards == nil {
		return map[string]string{}, nil
	}
	return cfg.Forwards, nil
}

// SetDomainForward upserts a strictly-1:1 forward for localpart in the domain's
// config.toml [forwards] table. localpart "*" sets the catchall. A multi-target
// target is rejected (ErrMultiTargetForward) before any write.
//
// The file is rewritten via a go-toml round-trip: all known config fields are
// preserved, but formatting and comments are normalized. This is acceptable for
// the current operator-managed config; a comment-preserving editor is tracked
// for the shared userctl/webadmin helper work.
func SetDomainForward(domainsPath, domain, localpart, target string) error {
	lp := strings.ToLower(strings.TrimSpace(localpart))
	if lp == "" {
		return fmt.Errorf("empty localpart")
	}
	normTarget, err := ValidateForwardTarget(target)
	if err != nil {
		return err
	}

	path := domainConfigPath(domainsPath, domain)
	if err := requireDomainDir(path, domain); err != nil {
		return err
	}

	cfg, err := loadOrEmptyDomainConfig(path)
	if err != nil {
		return err
	}
	if cfg.Forwards == nil {
		cfg.Forwards = map[string]string{}
	}
	cfg.Forwards[lp] = normTarget
	return writeDomainConfig(path, cfg)
}

// DeleteDomainForward removes the forward for localpart from the domain's
// config.toml [forwards] table. It returns (false, nil) when no such entry
// exists (a no-op), and (true, nil) after a successful removal.
func DeleteDomainForward(domainsPath, domain, localpart string) (bool, error) {
	lp := strings.ToLower(strings.TrimSpace(localpart))

	path := domainConfigPath(domainsPath, domain)
	if err := requireDomainDir(path, domain); err != nil {
		return false, err
	}

	cfg, err := loadOrEmptyDomainConfig(path)
	if err != nil {
		return false, err
	}
	if _, ok := cfg.Forwards[lp]; !ok {
		return false, nil
	}
	delete(cfg.Forwards, lp)
	return true, writeDomainConfig(path, cfg)
}

// requireDomainDir returns ErrDomainNotFound if the domain's directory (the
// parent of its config.toml) does not exist -- userctl manages forwards for
// domains that are already provisioned.
func requireDomainDir(configPath, domain string) error {
	dir := filepath.Dir(configPath)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: %q (no directory at %s)", ErrDomainNotFound, domain, dir)
	}
	return nil
}

// writeDomainConfig marshals cfg and writes it to path atomically (temp file in
// the same directory + fsync + rename), preserving the existing file mode or
// defaulting to 0640.
func writeDomainConfig(path string, cfg *DomainConfig) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config.toml.*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}

	mode := os.FileMode(0o640)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod temp config: %w", err)
	}

	return os.Rename(tmpPath, path)
}
