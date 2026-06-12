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
