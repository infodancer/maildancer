package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
)

// DKIM sentinel errors.
var (
	ErrInvalidSelector   = errors.New("invalid DKIM selector")
	ErrDKIMKeyExists     = errors.New("DKIM key already exists for this selector")
	ErrDKIMNotConfigured = errors.New("DKIM is not configured for this domain")
)

// dkimSelectorRe validates selectors: a single lowercase DNS label.
var dkimSelectorRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// DKIMRecord describes a domain's DKIM signing setup: the selector, the
// private key location, and the DNS TXT record that publishes the public key.
type DKIMRecord struct {
	Selector string
	KeyPath  string // private key file (absolute)
	DNSName  string // <selector>._domainkey.<domain>
	DNSValue string // v=DKIM1; k=ed25519; p=<base64>
}

// DefaultDKIMSelector returns the date-stamped selector for the given time,
// e.g. "d202606". Rotating on the default produces distinct selectors so old
// signatures keep verifying while DNS serves the new key.
func DefaultDKIMSelector(now time.Time) string {
	return "d" + now.Format("200601")
}

// ValidDKIMSelector reports whether s is a valid selector: a single
// lowercase DNS label of at most 63 octets (RFC 6376 section 3.1).
func ValidDKIMSelector(s string) bool {
	return len(s) <= 63 && dkimSelectorRe.MatchString(s)
}

// CreateDKIMKey generates an Ed25519 DKIM keypair (RFC 8463) for the domain,
// writes the private key under {config}/{domain}/dkim/{selector}.key with
// owner-only permissions, points dkim.selector and dkim.private_key in the
// domain config at it, and returns the DNS TXT record to publish.
//
// Ed25519 is the only algorithm the signing path loads (see
// auth/domain.LoadDKIMKey); supporting RSA would require extending the loader.
//
// An empty selector defaults to DefaultDKIMSelector(time.Now()). When a key
// file already exists for the selector, the call fails with ErrDKIMKeyExists
// unless force is set. Other selectors' key files are never touched, so a
// rotation (create under a new selector) retains the old key for mail signed
// before the switch.
func (p Paths) CreateDKIMKey(domainName, selector string, force bool) (*DKIMRecord, error) {
	if !ValidDomainName(domainName) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(domainName) {
		return nil, ErrDomainNotFound
	}
	if selector == "" {
		selector = DefaultDKIMSelector(time.Now())
	}
	if !ValidDKIMSelector(selector) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSelector, selector)
	}

	unlock, err := p.lockDomain(domainName)
	if err != nil {
		return nil, err
	}
	defer unlock()

	dkimDir := filepath.Join(p.Config, domainName, "dkim")
	keyPath := filepath.Join(dkimDir, selector+".key")
	if _, err := os.Stat(keyPath); err == nil && !force {
		return nil, fmt.Errorf("%w: %s", ErrDKIMKeyExists, keyPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate DKIM key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("encode DKIM key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(dkimDir, 0o750); err != nil {
		return nil, fmt.Errorf("create dkim directory: %w", err)
	}
	if err := writeFileAtomic(keyPath, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write DKIM key: %w", err)
	}

	// Point the domain config at the new key. The path is stored relative to
	// the domain dir, matching how the session-manager loader resolves it.
	configPath := filepath.Join(p.Config, domainName, "config.toml")
	content, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config: %w", err)
	}
	content = PatchSectionValue(content, "dkim", "selector", QuoteString(selector))
	content = PatchSectionValue(content, "dkim", "private_key", QuoteString("dkim/"+selector+".key"))
	if err := writeFileAtomic(configPath, content, 0o640); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	return dkimRecord(domainName, selector, keyPath, pub), nil
}

// DKIMStatus returns the domain's current DKIM setup, deriving the DNS TXT
// record from the configured private key. Returns ErrDKIMNotConfigured when
// the domain config has no selector or key path.
func (p Paths) DKIMStatus(domainName string) (*DKIMRecord, error) {
	if !ValidDomainName(domainName) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(domainName) {
		return nil, ErrDomainNotFound
	}

	domainDir := filepath.Join(p.Config, domainName)
	cfg, err := domain.LoadDomainConfig(filepath.Join(domainDir, "config.toml"))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if cfg.DKIM.Selector == "" || cfg.DKIM.PrivateKeyPath == "" {
		return nil, ErrDKIMNotConfigured
	}

	keyPath := cfg.DKIM.PrivateKeyPath
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(domainDir, keyPath)
	}
	signer, err := domain.LoadDKIMKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load DKIM key: %w", err)
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("DKIM key %s is not Ed25519", keyPath)
	}

	return dkimRecord(domainName, cfg.DKIM.Selector, keyPath, pub), nil
}

// dkimRecord assembles the DKIMRecord for a domain, selector, and public key.
func dkimRecord(domainName, selector, keyPath string, pub ed25519.PublicKey) *DKIMRecord {
	return &DKIMRecord{
		Selector: selector,
		KeyPath:  keyPath,
		DNSName:  selector + "._domainkey." + domainName,
		DNSValue: "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub),
	}
}
