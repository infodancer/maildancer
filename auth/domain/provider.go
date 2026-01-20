package domain

// DomainProvider maps email domains to their authentication configuration.
type DomainProvider interface {
	// GetDomain returns the Domain for a given domain name.
	// Returns nil if the domain is not handled by this server.
	GetDomain(name string) *Domain

	// Domains returns the list of domain names handled by this provider.
	Domains() []string

	// Close releases resources for all loaded domains.
	Close() error
}
