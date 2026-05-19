package authoidc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
)

// sweepInterval is how often the background goroutine drops expired codes and
// sessions from the store. Five minutes matches the "every few minutes" cadence
// established by domain/ratelimit.go's cleanup comment.
const sweepInterval = 5 * time.Minute

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
	store   Store
	domains map[string]*domainEntry

	sweepCancel context.CancelFunc
	sweepDone   chan struct{}
}

// New builds a Server from cfg, loading/generating keypairs and auth agents for
// every domain referenced in the client list. The store is a SQLite database
// at {DataDir}/oidc-state.db — co-located with per-domain signing keys under
// DataDir because OIDC state is server-private, not domain-admin editable.
func New(cfg *Config) (*Server, error) {
	store, err := newSQLiteStore(filepath.Join(cfg.Server.DataDir, "oidc-state.db"), nil)
	if err != nil {
		return nil, fmt.Errorf("init store: %w", err)
	}

	s := &Server{
		cfg:     cfg,
		keys:    newKeyStore(),
		store:   store,
		domains: make(map[string]*domainEntry),
	}

	seen := make(map[string]struct{})
	for _, c := range cfg.Clients {
		if _, ok := seen[c.Domain]; ok {
			continue
		}
		seen[c.Domain] = struct{}{}
		if err := s.loadDomain(c.Domain); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("domain %s: %w", c.Domain, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.sweepCancel = cancel
	s.sweepDone = make(chan struct{})
	go s.sweepLoop(ctx)

	return s, nil
}

// sweepLoop ticks every sweepInterval and removes expired codes and sessions
// from the store. Exits when ctx is cancelled.
func (s *Server) sweepLoop(ctx context.Context) {
	defer close(s.sweepDone)
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := s.store.SweepExpired(now); err != nil {
				slog.Warn("authoidc: sweep failed", "err", err)
			}
		}
	}
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

// Close stops the sweep goroutine, then releases resources held by all domain
// agents and the store.
func (s *Server) Close() error {
	if s.sweepCancel != nil {
		s.sweepCancel()
	}
	if s.sweepDone != nil {
		<-s.sweepDone
	}
	for _, de := range s.domains {
		_ = de.agent.Close()
	}
	if s.store != nil {
		_ = s.store.Close()
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

// validateRedirectURIScheme returns an error if rawURI is not a valid redirect
// URI for RFC 7591 dynamic client registration. HTTPS is required except for
// localhost/127.0.0.1/[::1], which are allowed for local development.
func validateRedirectURIScheme(rawURI string) error {
	u, err := url.Parse(rawURI)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid redirect_uri: %q", rawURI)
	}
	host := u.Hostname() // strips port and brackets from IPv6
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("redirect_uri must use https (got %q)", u.Scheme)
	}
	return nil
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
