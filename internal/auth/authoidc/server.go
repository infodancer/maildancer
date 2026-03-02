package authoidc

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
)

// domainEntry holds the runtime state for a configured domain.
type domainEntry struct {
	name    string
	agent   *passwd.Agent
	clients []ClientConfig
}

// Server is the auth-oidc HTTP server.
type Server struct {
	cfg     *Config
	keys    *keyStore
	store   *memStore
	domains map[string]*domainEntry
}

// New builds a Server from cfg, loading/generating keypairs and auth agents for
// every domain referenced in the client list.
func New(cfg *Config) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		keys:    newKeyStore(),
		store:   newMemStore(),
		domains: make(map[string]*domainEntry),
	}

	seen := make(map[string]struct{})
	for _, c := range cfg.Clients {
		if _, ok := seen[c.Domain]; ok {
			continue
		}
		seen[c.Domain] = struct{}{}
		if err := s.loadDomain(c.Domain); err != nil {
			return nil, fmt.Errorf("domain %s: %w", c.Domain, err)
		}
	}

	return s, nil
}

func (s *Server) loadDomain(name string) error {
	cfgPath := filepath.Join(s.cfg.Server.DomainDataPath, name, "config.toml")
	dc, err := domain.LoadDomainConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load domain config: %w", err)
	}

	domainDir := filepath.Join(s.cfg.Server.DomainDataPath, name)
	passwdPath := filepath.Join(domainDir, dc.Auth.CredentialBackend)
	keyDir := filepath.Join(domainDir, dc.Auth.KeyBackend)

	agent, err := passwd.NewAgent(passwdPath, keyDir)
	if err != nil {
		return fmt.Errorf("passwd agent: %w", err)
	}

	if err := s.keys.LoadOrGenerate(name, s.cfg.Server.DataDir); err != nil {
		_ = agent.Close()
		return fmt.Errorf("load keys: %w", err)
	}

	var clients []ClientConfig
	for _, c := range s.cfg.Clients {
		if c.Domain == name {
			clients = append(clients, c)
		}
	}

	s.domains[name] = &domainEntry{
		name:    name,
		agent:   agent,
		clients: clients,
	}
	return nil
}

// Close releases resources held by all domain agents.
func (s *Server) Close() error {
	for _, de := range s.domains {
		_ = de.agent.Close()
	}
	return nil
}

// Handler returns the root HTTP handler with all routes registered.
// Domain resolution is host-based: the Host header is matched against registered
// domains by stripping labels from the left until a match is found.
// For example, "auth.infodancer.net" resolves to the "infodancer.net" domain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /userinfo", s.userinfo)
	mux.HandleFunc("POST /logout", s.logout)

	return mux
}

// issuerBase returns the OIDC issuer string for the request.
// Since routing is host-based, the issuer is always scheme://host.
func issuerBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// domainForHost resolves the domain entry by progressively stripping labels from
// the left of the Host header until a registered domain is found or no candidates
// remain. Stops before bare TLDs (single label with no dot).
//
// Examples:
//
//	"auth.infodancer.net" → tries "auth.infodancer.net", then "infodancer.net"
//	"infodancer.net"      → tries "infodancer.net" directly
func (s *Server) domainForHost(w http.ResponseWriter, r *http.Request) (*domainEntry, bool) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	candidate := host
	for {
		if de, ok := s.domains[candidate]; ok {
			return de, true
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			break // single label, nowhere left to go
		}
		candidate = candidate[dot+1:]
		if !strings.Contains(candidate, ".") {
			break // next strip would leave a bare TLD
		}
	}
	http.Error(w, "unknown domain", http.StatusNotFound)
	return nil, false
}

// clientFor finds a registered client by ID within a domain entry.
// It checks static (config-file) clients first, then dynamically registered ones.
func (s *Server) clientFor(de *domainEntry, clientID string) (*ClientConfig, bool) {
	for i := range de.clients {
		if de.clients[i].ID == clientID {
			return &de.clients[i], true
		}
	}
	if rc, ok := s.store.LookupClient(de.name, clientID); ok {
		return &ClientConfig{
			Domain:       rc.Domain,
			ID:           rc.ClientID,
			RedirectURIs: rc.RedirectURIs,
			// Secret intentionally empty — dynamic clients are public (PKCE only).
		}, true
	}
	return nil, false
}

// validateRedirectURIDomain returns an error if the host of rawURI is not equal
// to or a subdomain of a registered domain. Used as defence-in-depth during
// RFC 7591 dynamic client registration.
func (s *Server) validateRedirectURIDomain(rawURI string) error {
	u, err := url.Parse(rawURI)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid redirect_uri: %q", rawURI)
	}
	host := u.Hostname() // strips port
	for domain := range s.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri host %q is not on a registered domain", host)
}

// validRedirectURI reports whether uri is registered for the client.
func validRedirectURI(client *ClientConfig, uri string) bool {
	for _, u := range client.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
