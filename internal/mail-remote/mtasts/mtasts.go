// Package mtasts implements MTA-STS (RFC 8461) policy discovery, caching,
// and MX matching for outbound direct delivery.
//
// The cache is load-bearing for security, not an optimization: a cached
// enforce policy is what protects deliveries during the window when an
// attacker blocks the policy TXT record or the policy host. Run with a
// persistent CacheDir wherever possible.
package mtasts

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// lookupTXT is the production TXT lookup, indirected for tests.
var lookupTXT = net.LookupTXT

// Policy modes (RFC 8461 section 3.2).
const (
	ModeEnforce = "enforce"
	ModeTesting = "testing"
	ModeNone    = "none"
)

// maxMaxAge caps the policy max_age field (RFC 8461: up to 1 year plus
// leap; 31557600 seconds).
const maxMaxAge = 31557600

// maxPolicySize caps the policy body read from the policy host.
const maxPolicySize = 64 * 1024

// Policy is a parsed MTA-STS policy.
type Policy struct {
	Mode   string   `json:"mode"`
	MXs    []string `json:"mxs"`
	MaxAge int      `json:"max_age"` // seconds
}

// MXMatches reports whether the MX hostname is permitted by the policy's
// mx patterns. A leading "*." wildcard matches exactly one additional
// leftmost label (RFC 8461 section 4.1). Comparison is case-insensitive.
func (p *Policy) MXMatches(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pattern := range p.MXs {
		pat := strings.ToLower(strings.TrimSuffix(pattern, "."))
		if rest, ok := strings.CutPrefix(pat, "*."); ok {
			suffix := "." + rest
			label, found := strings.CutSuffix(h, suffix)
			if found && label != "" && !strings.Contains(label, ".") {
				return true
			}
			continue
		}
		if h == pat {
			return true
		}
	}
	return false
}

// ParsePolicy parses an MTA-STS policy body (RFC 8461 section 3.2).
func ParsePolicy(body string) (*Policy, error) {
	p := &Policy{MaxAge: -1}
	version := ""
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "version":
			version = value
		case "mode":
			p.Mode = value
		case "mx":
			p.MXs = append(p.MXs, value)
		case "max_age":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid max_age %q", value)
			}
			if n > maxMaxAge {
				n = maxMaxAge
			}
			p.MaxAge = n
		}
	}

	if version != "STSv1" {
		return nil, fmt.Errorf("unsupported policy version %q", version)
	}
	switch p.Mode {
	case ModeEnforce, ModeTesting, ModeNone:
	default:
		return nil, fmt.Errorf("invalid mode %q", p.Mode)
	}
	if p.Mode == ModeEnforce && len(p.MXs) == 0 {
		return nil, fmt.Errorf("enforce policy lists no mx patterns")
	}
	if p.MaxAge < 0 {
		return nil, fmt.Errorf("missing max_age")
	}
	return p, nil
}

// parseTXT extracts the policy id from _mta-sts TXT records. Returns
// ok=false when no valid STSv1 record exists, including the RFC 8461 case
// of multiple STSv1 records (senders must treat that as no policy).
func parseTXT(records []string) (id string, ok bool) {
	found := 0
	for _, rec := range records {
		fields := strings.Split(rec, ";")
		if strings.TrimSpace(fields[0]) != "v=STSv1" {
			continue
		}
		found++
		for _, f := range fields[1:] {
			if v, isID := strings.CutPrefix(strings.TrimSpace(f), "id="); isID {
				id = strings.TrimSpace(v)
			}
		}
	}
	if found != 1 || id == "" {
		return "", false
	}
	return id, true
}

// TXTResolver looks up TXT records; *net.Resolver-style implementations
// or fakes both fit.
type TXTResolver interface {
	LookupTXT(name string) ([]string, error)
}

// netTXTResolver adapts the package-level net lookup.
type netTXTResolver struct{}

func (netTXTResolver) LookupTXT(name string) ([]string, error) {
	return lookupTXT(name)
}

// Checker discovers, caches, and serves MTA-STS policies.
type Checker struct {
	Resolver TXTResolver
	// Fetch retrieves the policy body for a domain. Defaults to HTTPS
	// against https://mta-sts.<domain>/.well-known/mta-sts.txt.
	Fetch func(domain string) (string, error)
	// CacheDir holds cached policies, one JSON file per domain. Empty
	// disables caching -- legal, but weakens the persistence property
	// (see the package comment).
	CacheDir string
	Now      func() time.Time
}

// NewChecker returns a Checker with production defaults and the given
// cache directory ("" = no cache).
func NewChecker(cacheDir string) *Checker {
	return &Checker{
		Resolver: netTXTResolver{},
		Fetch:    HTTPSFetcher(30 * time.Second),
		CacheDir: cacheDir,
		Now:      time.Now,
	}
}

// cacheEntry is the on-disk cache record for one domain.
type cacheEntry struct {
	ID        string    `json:"id"`
	FetchedAt time.Time `json:"fetched_at"`
	Policy    Policy    `json:"policy"`
}

// PolicyFor returns the effective MTA-STS policy for domain, or (nil, nil)
// when the domain publishes none. Cached policies are served while fresh;
// per RFC 8461 a cached policy outlives TXT-lookup and policy-fetch
// failures so an attacker cannot downgrade by blocking either.
func (c *Checker) PolicyFor(domain string) (*Policy, error) {
	cached := c.loadCache(domain)

	id, hasTXT := c.lookupID(domain)
	if !hasTXT {
		if cached != nil && c.fresh(cached) {
			return &cached.Policy, nil
		}
		return nil, nil
	}

	if cached != nil && cached.ID == id && c.fresh(cached) {
		return &cached.Policy, nil
	}

	body, err := c.Fetch(domain)
	if err == nil {
		var p *Policy
		if p, err = ParsePolicy(body); err == nil {
			c.storeCache(domain, &cacheEntry{ID: id, FetchedAt: c.Now(), Policy: *p})
			return p, nil
		}
	}

	// Fetch or parse failed: fall back to a still-fresh cached policy.
	if cached != nil && c.fresh(cached) {
		return &cached.Policy, nil
	}
	return nil, fmt.Errorf("mta-sts policy for %s unavailable: %w", domain, err)
}

// lookupID returns the policy id from the domain's _mta-sts TXT record.
func (c *Checker) lookupID(domain string) (string, bool) {
	records, err := c.Resolver.LookupTXT("_mta-sts." + domain)
	if err != nil {
		return "", false
	}
	return parseTXT(records)
}

// fresh reports whether the cache entry is within its policy's max_age.
func (c *Checker) fresh(e *cacheEntry) bool {
	return c.Now().Before(e.FetchedAt.Add(time.Duration(e.Policy.MaxAge) * time.Second))
}

// cachePath returns the cache file path for a domain.
func (c *Checker) cachePath(domain string) string {
	return filepath.Join(c.CacheDir, url.PathEscape(strings.ToLower(domain))+".json")
}

func (c *Checker) loadCache(domain string) *cacheEntry {
	if c.CacheDir == "" {
		return nil
	}
	data, err := os.ReadFile(c.cachePath(domain))
	if err != nil {
		return nil
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil
	}
	return &e
}

func (c *Checker) storeCache(domain string, e *cacheEntry) {
	if c.CacheDir == "" {
		return
	}
	if err := os.MkdirAll(c.CacheDir, 0o750); err != nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	path := c.cachePath(domain)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// HTTPSFetcher returns the production policy fetcher: HTTPS with verified
// certificates against the well-known policy URL, refusing redirects
// (RFC 8461 section 3.3) and capping the body size.
func HTTPSFetcher(timeout time.Duration) func(domain string) (string, error) {
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: refuseRedirect,
	}
	return newFetcher(client, func(domain string) string {
		return "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	})
}

// newFetcher builds a fetch function from a client and URL scheme;
// separated so tests can point it at a local TLS server.
func newFetcher(client *http.Client, urlFor func(domain string) string) func(string) (string, error) {
	return func(domain string) (string, error) {
		resp, err := client.Get(urlFor(domain))
		if err != nil {
			return "", fmt.Errorf("fetch policy: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("fetch policy: HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize))
		if err != nil {
			return "", fmt.Errorf("read policy: %w", err)
		}
		return string(body), nil
	}
}

// refuseRedirect rejects all HTTP redirects (RFC 8461 section 3.3).
func refuseRedirect(_ *http.Request, _ []*http.Request) error {
	return fmt.Errorf("mta-sts policy fetch must not follow redirects")
}
