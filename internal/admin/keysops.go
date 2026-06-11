package admin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/internal/admin/keys"
)

// domainKeyName is the reserved key-file basename for a domain's own keypair.
const domainKeyName = "domain"

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
	return p.keyStatus(domain, username), nil
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

	if err := p.createKeypair(domain, username, password); err != nil {
		return "", err
	}
	status := p.keyStatus(domain, username)
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
	return keys.DeleteKeypair(filepath.Join(p.Config, domain, "keys"), username)
}

// DomainKeyStatus returns the keypair status for the domain key.
func (p Paths) DomainKeyStatus(domain string) (*KeyStatus, error) {
	if !ValidDomainName(domain) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return nil, ErrDomainNotFound
	}
	return p.keyStatus(domain, domainKeyName), nil
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
	status := p.keyStatus(domain, domainKeyName)
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
	return keys.DeleteKeypair(filepath.Join(p.Config, domain, "keys"), domainKeyName)
}

// createKeypair generates and saves a password-encrypted keypair.
func (p Paths) createKeypair(domain, name, password string) error {
	pub, encPriv, err := keys.GenerateKeypair(password)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	keysDir := filepath.Join(p.Config, domain, "keys")
	if err := keys.SaveKeypair(keysDir, name, pub, encPriv); err != nil {
		return fmt.Errorf("save keypair: %w", err)
	}
	return nil
}

// keyStatus reads keypair presence and fingerprint for a key-file basename.
func (p Paths) keyStatus(domain, name string) *KeyStatus {
	keysDir := filepath.Join(p.Config, domain, "keys")
	pub, err := keys.LoadPublicKey(keysDir, name)
	if err != nil {
		return &KeyStatus{Exists: false}
	}
	_, privErr := os.Stat(filepath.Join(keysDir, name+".key"))
	return &KeyStatus{
		Exists:      true,
		Fingerprint: keys.PublicKeyFingerprint(pub),
		HasPrivate:  privErr == nil,
	}
}
