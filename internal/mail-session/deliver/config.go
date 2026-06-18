// Package deliver orchestrates the full delivery pipeline: forwarding resolution,
// sieve execution, and final maildir write.
package deliver

// Config holds the runtime configuration for the delivery pipeline.
type Config struct {
	// DomainsPath is the directory containing per-domain config subdirectories.
	DomainsPath string `toml:"domains_path"`

	// DomainsDataPath is the directory containing per-domain mail data.
	// Defaults to DomainsPath when empty.
	DomainsDataPath string `toml:"domains_data_path"`

	// StoreBasePath is the recipient's user-store root ({data}/{domain}/users),
	// resolved by session-manager (as root) and passed to mail-session via
	// --basepath. At-rest encryption reads the recipient's keyring directly from
	// here ({StoreBasePath}/{localpart}/keyring.pub) -- the recipient owns and
	// can read it -- instead of via the config-tree-dependent domain provider,
	// which the recipient uid cannot reach (maildancer#86).
	StoreBasePath string `toml:"-"`

	// MaxMessageSize is the maximum message body size in bytes.
	// Defaults to 50 MiB when zero.
	MaxMessageSize int64 `toml:"max_message_size"`

	// DeliveryTimeout is the maximum time allowed for the full delivery pipeline.
	// Defaults to "60s" when empty or unparseable.
	DeliveryTimeout string `toml:"delivery_timeout"`
}

// DataPath returns the effective data path: DomainsDataPath if set, else DomainsPath.
func (c *Config) DataPath() string {
	if c.DomainsDataPath != "" {
		return c.DomainsDataPath
	}
	return c.DomainsPath
}
