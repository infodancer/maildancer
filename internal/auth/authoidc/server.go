package authoidc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/passwd"
)

// Defaults for signing-key lifecycle. Each becomes configurable in a later
// commit; the values here match docs/signing-key-rotation.md.
const (
	defaultKeyRetentionAfterRetire  = 24 * time.Hour
	defaultKeyRotationInterval      = 90 * 24 * time.Hour
	defaultKeyRotationCheckInterval = 24 * time.Hour
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

	rotatorCancel context.CancelFunc
	rotatorDone   chan struct{}
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

	sweepCtx, cancelSweep := context.WithCancel(context.Background())
	s.sweepCancel = cancelSweep
	s.sweepDone = make(chan struct{})
	go s.sweepLoop(sweepCtx)

	rotCtx, cancelRot := context.WithCancel(context.Background())
	s.rotatorCancel = cancelRot
	s.rotatorDone = make(chan struct{})
	go s.rotatorLoop(rotCtx)

	return s, nil
}

// sweepLoop ticks every sweepInterval, removing expired codes/sessions and
// expired signing keys (with their on-disk PEM files). Exits when ctx is
// cancelled.
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
			s.sweepSigningKeys(now)
		}
	}
}

// sweepSigningKeys removes any retiring keys whose retention window has
// elapsed, unlinks their PEM files, and drops the cache entries. File
// unlink is best-effort; the DB row deletion is the authoritative state
// change.
func (s *Server) sweepSigningKeys(now time.Time) {
	swept, err := s.store.SweepExpiredSigningKeys(now)
	if err != nil {
		slog.Warn("authoidc: sweep signing keys failed", "err", err)
		return
	}
	for _, rec := range swept {
		path := keyFilePath(s.cfg.Server.DataDir, rec.Domain, rec.KID)
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("authoidc: unlink retired key file",
				"domain", rec.Domain, "kid", rec.KID, "path", path, "err", err)
		}
		s.keys.Drop(rec.Domain, rec.KID)
		slog.Info("authoidc: swept retired signing key",
			"event", "key_swept", "domain", rec.Domain, "kid", rec.KID)
	}
}

// rotatorLoop checks daily whether any domain's current signing key is
// older than the rotation interval; rotates each that is. Exits when ctx
// is cancelled.
func (s *Server) rotatorLoop(ctx context.Context) {
	defer close(s.rotatorDone)
	t := time.NewTicker(defaultKeyRotationCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.rotateAgedKeys(time.Now())
		}
	}
}

// rotateAgedKeys iterates every loaded domain and rotates the current key
// if it exceeds the rotation interval. Failures are logged per-domain so
// one bad domain doesn't stall rotation for the rest.
func (s *Server) rotateAgedKeys(now time.Time) {
	for name := range s.domains {
		rows, err := s.store.ListSigningKeys(name)
		if err != nil {
			slog.Warn("authoidc: rotator list failed", "domain", name, "err", err)
			continue
		}
		for _, rec := range rows {
			if rec.State != keyStateCurrent {
				continue
			}
			if now.Sub(rec.CreatedAt) < defaultKeyRotationInterval {
				continue
			}
			if _, err := s.rotateKey(name, ""); err != nil {
				slog.Warn("authoidc: scheduled rotation failed",
					"domain", name, "err", err)
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

	if err := s.ensureSigningKeys(name); err != nil {
		_ = agent.Close()
		return fmt.Errorf("ensure signing keys: %w", err)
	}
	if err := s.primeKeyCache(name); err != nil {
		_ = agent.Close()
		return fmt.Errorf("prime key cache: %w", err)
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

// Close stops the background goroutines, then releases resources held by
// all domain agents and the store.
func (s *Server) Close() error {
	if s.rotatorCancel != nil {
		s.rotatorCancel()
	}
	if s.sweepCancel != nil {
		s.sweepCancel()
	}
	if s.rotatorDone != nil {
		<-s.rotatorDone
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

// --- signing-key plumbing (see docs/signing-key-rotation.md) ---

// ensureSigningKeys guarantees that the signing_keys table has at least one
// row for domain. Three cases:
//
//  1. Rows already exist — nothing to do; primeKeyCache will load them.
//  2. No rows, but the legacy {data_dir}/{domain}/signing.key exists —
//     migrate it: move to keys/{domain}-1.key and insert one row with
//     algorithm=RS256, state=current, created_at = file mtime. The legacy
//     kid {domain}-1 is preserved so tokens signed before the upgrade still
//     verify against the migrated key in JWKS.
//  3. No rows and no legacy file — fresh install: generate a new keypair
//     with the default algorithm and record it as current.
func (s *Server) ensureSigningKeys(domain string) error {
	rows, err := s.store.ListSigningKeys(domain)
	if err != nil {
		return fmt.Errorf("list signing keys: %w", err)
	}
	if len(rows) > 0 {
		return nil
	}

	legacyPath := filepath.Join(s.cfg.Server.DataDir, domain, "signing.key")
	info, err := os.Stat(legacyPath)
	switch {
	case err == nil:
		newKID := domain + "-1"
		if err := os.MkdirAll(keyDir(s.cfg.Server.DataDir, domain), 0o700); err != nil {
			return fmt.Errorf("create key dir: %w", err)
		}
		target := keyFilePath(s.cfg.Server.DataDir, domain, newKID)
		if err := os.Rename(legacyPath, target); err != nil {
			return fmt.Errorf("migrate legacy key: %w", err)
		}
		rec := signingKeyRecord{
			Domain:    domain,
			KID:       newKID,
			Algorithm: AlgRS256,
			State:     keyStateCurrent,
			CreatedAt: info.ModTime(),
		}
		if err := s.store.InsertSigningKey(rec); err != nil {
			return fmt.Errorf("record migrated key: %w", err)
		}
		slog.Info("authoidc: migrated legacy signing key",
			"event", "key_migration", "domain", domain, "kid", newKID)
		return nil
	case errors.Is(err, fs.ErrNotExist):
		// fall through to fresh-install path
	default:
		return fmt.Errorf("stat legacy key: %w", err)
	}

	now := time.Now()
	newKID := fmt.Sprintf("%s-%d", domain, now.UnixNano())
	alg := AlgES256 // default per docs/signing-key-rotation.md; configurable later
	if _, err := generateAndWriteKey(s.cfg.Server.DataDir, domain, newKID, alg); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	rec := signingKeyRecord{
		Domain:    domain,
		KID:       newKID,
		Algorithm: alg,
		State:     keyStateCurrent,
		CreatedAt: now,
	}
	if err := s.store.InsertSigningKey(rec); err != nil {
		return fmt.Errorf("record new key: %w", err)
	}
	slog.Info("authoidc: generated initial signing key",
		"event", "key_generated", "domain", domain, "kid", newKID, "algorithm", alg)
	return nil
}

// primeKeyCache loads every signing key for domain from disk into the
// in-memory keyStore cache so the first request after startup doesn't pay
// the PEM-parse cost. Any retiring key whose retention has already lapsed
// is loaded too — the sweep will discard it shortly.
func (s *Server) primeKeyCache(domain string) error {
	rows, err := s.store.ListSigningKeys(domain)
	if err != nil {
		return fmt.Errorf("list signing keys: %w", err)
	}
	for _, rec := range rows {
		if _, err := s.loadKeyFromRecord(rec); err != nil {
			return fmt.Errorf("load key %s: %w", rec.KID, err)
		}
	}
	return nil
}

// loadKeyFromRecord returns the loaded JWK for rec, reading the PEM file on
// cache miss. Subsequent calls for the same kid hit the cache.
func (s *Server) loadKeyFromRecord(rec signingKeyRecord) (*loadedKey, error) {
	if k, ok := s.keys.Get(rec.Domain, rec.KID); ok {
		return k, nil
	}
	k, err := loadKeyFile(s.cfg.Server.DataDir, rec.Domain, rec.KID, rec.Algorithm)
	if err != nil {
		return nil, err
	}
	s.keys.Put(rec.Domain, k)
	return k, nil
}

// currentKeyFor queries the Store for the current signing key for domain
// and returns the loaded JWK. Called on every signing request — this is
// option (a) from the design's reload-coordination open question (one
// indexed query per token issuance, no inotify/SIGHUP coordination needed).
func (s *Server) currentKeyFor(domain string) (*loadedKey, error) {
	rows, err := s.store.ListSigningKeys(domain)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	for _, rec := range rows {
		if rec.State == keyStateCurrent {
			return s.loadKeyFromRecord(rec)
		}
	}
	return nil, fmt.Errorf("no current signing key for domain %s", domain)
}

// activePublicJWKsFor returns the union of public JWKs for domain that a
// relying party might need to verify a token: current + retiring keys whose
// retention window has not yet lapsed. Drives /jwks.json and the
// verification keyset for /userinfo.
func (s *Server) activePublicJWKsFor(domain string) (jwk.Set, error) {
	rows, err := s.store.ListSigningKeys(domain)
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}
	now := time.Now()
	set := jwk.NewSet()
	for _, rec := range rows {
		if rec.State == keyStateRetiring && !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt) {
			continue
		}
		k, err := s.loadKeyFromRecord(rec)
		if err != nil {
			return nil, err
		}
		if err := set.AddKey(k.pubJWK); err != nil {
			return nil, fmt.Errorf("add jwk: %w", err)
		}
	}
	return set, nil
}

// rotateKey performs one full rotation for domain: generate a new keypair
// for algorithm (or the default if empty), write the file, atomically swap
// current+retiring in the Store, prime the cache, and log the event. Used
// by both the scheduled rotator and the userctl CLI.
//
// The slog message uses event=key_rotation as a stable label so an external
// counter (Prometheus exporter, log aggregator) can lift the rate without
// requiring a metrics endpoint in auth-oidc itself. Adding a /metrics
// surface and a native counter is a follow-up (see docs/signing-key-rotation.md
// "Open questions" #2).
func (s *Server) rotateKey(domain, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = AlgES256 // configurable in a later commit
	}
	if _, err := jwaAlgorithm(algorithm); err != nil {
		return "", err
	}
	now := time.Now()
	newKID := fmt.Sprintf("%s-%d", domain, now.UnixNano())
	loaded, err := generateAndWriteKey(s.cfg.Server.DataDir, domain, newKID, algorithm)
	if err != nil {
		return "", err
	}
	rec := signingKeyRecord{
		Domain:    domain,
		KID:       newKID,
		Algorithm: algorithm,
		State:     keyStateCurrent,
		CreatedAt: now,
	}
	if err := s.store.RotateSigningKey(domain, rec, defaultKeyRetentionAfterRetire); err != nil {
		return "", fmt.Errorf("rotate signing key: %w", err)
	}
	s.keys.Put(domain, loaded)
	slog.Info("authoidc: rotated signing key",
		"event", "key_rotation",
		"domain", domain,
		"kid", newKID,
		"algorithm", algorithm,
	)
	return newKID, nil
}

// revokeKey marks an existing key as expired immediately. Operator-initiated:
// the caller has decided to accept that any token signed by this kid will
// fail validation as soon as the sweep removes the row.
func (s *Server) revokeKey(domain, kid string) error {
	if err := s.store.RevokeSigningKey(domain, kid); err != nil {
		return err
	}
	slog.Warn("authoidc: revoked signing key",
		"event", "key_revoked",
		"domain", domain,
		"kid", kid,
	)
	return nil
}

// activeAlgorithmsFor returns the sorted set union of JWA algorithm strings
// across all current + non-expired retiring keys for domain. Drives the
// discovery document's id_token_signing_alg_values_supported.
func (s *Server) activeAlgorithmsFor(domain string) ([]string, error) {
	rows, err := s.store.ListSigningKeys(domain)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	seen := map[string]struct{}{}
	var out []string
	for _, rec := range rows {
		if rec.State == keyStateRetiring && !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt) {
			continue
		}
		if _, ok := seen[rec.Algorithm]; ok {
			continue
		}
		seen[rec.Algorithm] = struct{}{}
		out = append(out, rec.Algorithm)
	}
	sort.Strings(out)
	return out, nil
}
