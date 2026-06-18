package admin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/auth/identity"
	"github.com/infodancer/maildancer/internal/admin/keys"
)

// domainKeyName is the reserved key-file basename for a domain's own keypair.
const domainKeyName = "domain"

// keyringName is the basename of a per-user keyring: keyring.pub / keyring.key.
// Per-user keyrings live in the writable data tree beside the user's maildir
// (not the read-only config tree) so the delivery process -- running as the
// recipient uid -- can read its own public key without config-tree access
// (maildancer#82).
const keyringName = "keyring"

// userKeyringBase returns the parent of per-user data directories for a domain:
// {Data}/{domain}/users. This is the value passed to a passwd agent's
// WithUserKeyringBase so it resolves {base}/{user}/keyring.{key,pub}.
func (p Paths) userKeyringBase(domain string) string {
	return filepath.Join(p.Data, domain, "users")
}

// userKeyringDir returns the data-tree directory that holds a user's keyring,
// beside their maildir: {Data}/{domain}/users/{username}.
func (p Paths) userKeyringDir(domain, username string) string {
	return filepath.Join(p.userKeyringBase(domain), username)
}

// domainKeysDir returns the config-tree directory that holds domain-level keys.
// Domain keys are not read by a per-user delivery process, so they stay in the
// config tree.
func (p Paths) domainKeysDir(domain string) string {
	return filepath.Join(p.Config, domain, "keys")
}

// KeyStatus describes the encryption keypair state for a user or domain.
type KeyStatus struct {
	Exists      bool
	Fingerprint string
	HasPrivate  bool
}

// UserKeyStatus returns the keypair status for a user.
func (p Paths) UserKeyStatus(domain, username string) (*KeyStatus, error) {
	if !ValidDomainName(domain) {
		return nil, ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return nil, ErrInvalidUsername
	}
	if !p.DomainExists(domain) {
		return nil, ErrDomainNotFound
	}
	return p.userKeyStatus(domain, username), nil
}

// CreateUserKeys generates a keypair for an existing user, encrypted with
// password, and returns the public-key fingerprint.
func (p Paths) CreateUserKeys(domain, username, password string) (string, error) {
	if !ValidDomainName(domain) {
		return "", ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return "", ErrInvalidUsername
	}
	if password == "" {
		return "", ErrPasswordRequired
	}
	if !p.DomainExists(domain) {
		return "", ErrDomainNotFound
	}
	if !userExists(filepath.Join(p.Config, domain, "passwd"), username) {
		return "", ErrUserNotFound
	}

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return "", err
	}
	defer unlock()

	if _, err := p.createUserKeypair(domain, username, password); err != nil {
		return "", err
	}
	status := p.userKeyStatus(domain, username)
	return status.Fingerprint, nil
}

// DeleteUserKeys removes a user's keypair files.
func (p Paths) DeleteUserKeys(domain, username string) error {
	if !ValidDomainName(domain) {
		return ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	if !p.DomainExists(domain) {
		return ErrDomainNotFound
	}
	// Remove the data-tree keyring and any legacy config-tree key files.
	if err := keys.DeleteKeypair(p.userKeyringDir(domain, username), keyringName); err != nil {
		return err
	}
	return keys.DeleteKeypair(p.domainKeysDir(domain), username)
}

// DomainKeyStatus returns the keypair status for the domain key.
func (p Paths) DomainKeyStatus(domain string) (*KeyStatus, error) {
	if !ValidDomainName(domain) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return nil, ErrDomainNotFound
	}
	return p.keyStatus(p.domainKeysDir(domain), domainKeyName), nil
}

// CreateDomainKeys generates the domain keypair, encrypted with password,
// and returns the public-key fingerprint.
func (p Paths) CreateDomainKeys(domain, password string) (string, error) {
	if !ValidDomainName(domain) {
		return "", ErrInvalidDomainName
	}
	if password == "" {
		return "", ErrPasswordRequired
	}
	if !p.DomainExists(domain) {
		return "", ErrDomainNotFound
	}

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return "", err
	}
	defer unlock()

	if err := p.createKeypair(domain, domainKeyName, password); err != nil {
		return "", err
	}
	status := p.keyStatus(p.domainKeysDir(domain), domainKeyName)
	return status.Fingerprint, nil
}

// DeleteDomainKeys removes the domain keypair files.
func (p Paths) DeleteDomainKeys(domain string) error {
	if !ValidDomainName(domain) {
		return ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return ErrDomainNotFound
	}
	return keys.DeleteKeypair(p.domainKeysDir(domain), domainKeyName)
}

// createKeypair generates and saves a password-encrypted DOMAIN keypair in the
// config tree. User keypairs go through createUserKeypair (data tree).
func (p Paths) createKeypair(domain, name, password string) error {
	pub, encPriv, err := keys.GenerateKeypair(password)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	if err := keys.SaveKeypair(p.domainKeysDir(domain), name, pub, encPriv); err != nil {
		return fmt.Errorf("save keypair: %w", err)
	}
	return nil
}

// createUserKeypair generates a user's keypair and writes it into the user's
// data-tree directory as keyring.pub / keyring.key, then applies ownership
// (uid:gid 0700) so the delivery process -- running as the recipient -- can
// read it. The returned warnings hold non-fatal ownership problems; an
// unreadable keyring fails delivery closed rather than silently storing
// plaintext (maildancer#82), so a misowned keyring is worth surfacing.
func (p Paths) createUserKeypair(domain, username, password string) ([]string, error) {
	pub, encPriv, err := keys.GenerateKeypair(password)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	dir := p.userKeyringDir(domain, username)
	if err := keys.SaveKeypair(dir, keyringName, pub, encPriv); err != nil {
		return nil, fmt.Errorf("save keypair: %w", err)
	}
	if warn := p.applyKeyringOwnership(domain, username, dir); warn != "" {
		return []string{warn}, nil
	}
	return nil, nil
}

// applyKeyringOwnership chowns the user keyring directory and files to the
// user's uid and the domain gid and tightens the directory mode to 0700. It is
// a no-op when the process is not root (ownership requires privilege and the
// uid/gid privilege-separation model is only in play under root); production
// userctl/webadmin run as root. Returns a human-readable warning when
// ownership cannot be applied, empty on success.
func (p Paths) applyKeyringOwnership(domain, username, dir string) string {
	if os.Geteuid() != 0 {
		return ""
	}
	uid, err := identity.UserUID(p.Config, domain, username)
	if err != nil {
		return fmt.Sprintf("keyring ownership: lookup uid: %v", err)
	}
	gid, err := p.domainGid(domain)
	if err != nil {
		return fmt.Sprintf("keyring ownership: lookup gid: %v", err)
	}
	if uid == 0 || gid == 0 {
		return fmt.Sprintf("keyring left owned by the current user: %s@%s has no uid/gid yet (uid=%d gid=%d)", username, domain, uid, gid)
	}
	_ = os.Chmod(dir, 0o700)
	for _, path := range []string{dir, filepath.Join(dir, keyringName+".pub"), filepath.Join(dir, keyringName+".key")} {
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			return fmt.Sprintf("keyring ownership: chown %s to %d:%d failed (delivery as the recipient cannot read it; mail fails closed rather than storing plaintext): %v", path, uid, gid, err)
		}
	}
	return ""
}

// domainGid reads the domain's allocated gid from the authoritative gid.toml
// map (via the identity package). Returns identity.ErrNoGID when the domain has
// no allocation yet.
func (p Paths) domainGid(domain string) (uint32, error) {
	return identity.DomainGID(p.Config, domain)
}

// keyStatus reads keypair presence and fingerprint for a key-file basename in
// the given directory.
func (p Paths) keyStatus(dir, name string) *KeyStatus {
	pub, err := keys.LoadPublicKey(dir, name)
	if err != nil {
		return &KeyStatus{Exists: false}
	}
	_, privErr := os.Stat(filepath.Join(dir, name+".key"))
	return &KeyStatus{
		Exists:      true,
		Fingerprint: keys.PublicKeyFingerprint(pub),
		HasPrivate:  privErr == nil,
	}
}

// userKeyFile returns the path of the user's sealed private key, preferring the
// data-tree keyring and falling back to the legacy config-tree location for
// unmigrated users. When neither exists it returns the canonical keyring path
// (maildancer#82).
func (p Paths) userKeyFile(domain, username string) string {
	keyring := filepath.Join(p.userKeyringDir(domain, username), keyringName+".key")
	if _, err := os.Stat(keyring); err == nil {
		return keyring
	}
	if legacy := filepath.Join(p.domainKeysDir(domain), username+".key"); fileExists(legacy) {
		return legacy
	}
	return keyring
}

// fileExists reports whether path names an existing file.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// userKeyStatus reports a user's keypair state, preferring the data-tree
// keyring and falling back to the legacy config-tree key file for unmigrated
// users (maildancer#82).
func (p Paths) userKeyStatus(domain, username string) *KeyStatus {
	if s := p.keyStatus(p.userKeyringDir(domain, username), keyringName); s.Exists {
		return s
	}
	return p.keyStatus(p.domainKeysDir(domain), username)
}
