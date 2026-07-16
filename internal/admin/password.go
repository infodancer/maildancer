package admin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/admin/keys"
)

// ChangePassword verifies the user's current password, updates the hash, and
// re-seals the private key under the new password when one exists. The
// keypair is preserved -- same public key, old encrypted mail stays readable.
// This is the user-initiated path; admins without the current password use
// ResetPasswordRegenKeys instead.
func (p Paths) ChangePassword(domain, username, oldPassword, newPassword string) error {
	if !ValidDomainName(domain) {
		return ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	if oldPassword == "" {
		return fmt.Errorf("%w: current password", ErrPasswordRequired)
	}
	if !ValidPassword(newPassword) {
		return fmt.Errorf("%w: minimum %d characters", ErrWeakPassword, MinPasswordLength)
	}
	if !p.DomainExists(domain) {
		return ErrDomainNotFound
	}

	passwdPath := filepath.Join(p.Config, domain, "passwd")
	keysDir := p.domainKeysDir(domain)

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return err
	}
	defer unlock()

	if !userExists(passwdPath, username) {
		return ErrUserNotFound
	}

	// Authenticate verifies the current password against the hash and, when
	// the user has keys, unseals the private key (a sealed key that does not
	// unseal fails authentication outright -- the strict no-silent-downgrade
	// invariant -- so reaching a session with a key means we can re-seal it).
	// The keyring lives in the data-tree user dir (legacy keysDir is a
	// read-fallback for unmigrated users); see maildancer#82.
	agent, err := passwd.NewAgent(passwdPath, keysDir)
	if err != nil {
		return fmt.Errorf("open auth agent: %w", err)
	}
	agent = agent.WithUserKeyringBase(p.userKeyringBase(domain))
	defer func() { _ = agent.Close() }()

	session, err := agent.Authenticate(context.Background(), username, oldPassword)
	if err != nil {
		return fmt.Errorf("current password verification failed: %w", err)
	}
	defer session.Clear()

	// Seal the key under the new password before touching the hash, then
	// swap it in with an atomic rename after the hash change -- the window
	// where hash and key disagree is a single rename syscall.
	var newKeyPath, tmpKeyPath string
	if session.PrivateKey != nil {
		encPriv, err := keys.EncryptPrivateKey(session.PrivateKey, newPassword)
		if err != nil {
			return fmt.Errorf("re-seal private key: %w", err)
		}
		newKeyPath = p.userKeyFile(domain, username)
		tmpKeyPath = newKeyPath + ".rekey"
		if err := os.WriteFile(tmpKeyPath, encPriv, 0o600); err != nil {
			return fmt.Errorf("write re-sealed key: %w", err)
		}
	}

	if err := passwd.SetPassword(passwdPath, username, newPassword); err != nil {
		if tmpKeyPath != "" {
			_ = os.Remove(tmpKeyPath)
		}
		return fmt.Errorf("update password: %w", err)
	}

	if tmpKeyPath != "" {
		if err := os.Rename(tmpKeyPath, newKeyPath); err != nil {
			return fmt.Errorf("activate re-sealed key (password already changed; key is sealed under the OLD password until this is fixed): %w", err)
		}
	}
	if err := p.provisionDomainConfigTree(domain); err != nil {
		return fmt.Errorf("config ownership: %w", err)
	}
	return nil
}

// ResetPasswordRegenKeys is the explicit admin reset for users who may have
// encryption keys: it replaces the password hash and, when the user had a
// sealed key, deletes the old keypair and generates a fresh one sealed under
// the new password. Old encrypted mail becomes permanently unreadable -- the
// honest no-escrow consequence of an admin reset. Returns the new keypair's
// fingerprint, or "" when the user had no keys (none are fabricated).
func (p Paths) ResetPasswordRegenKeys(domain, username, newPassword string) (string, error) {
	if !ValidDomainName(domain) {
		return "", ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return "", ErrInvalidUsername
	}
	if !ValidPassword(newPassword) {
		return "", fmt.Errorf("%w: minimum %d characters", ErrWeakPassword, MinPasswordLength)
	}
	if !p.DomainExists(domain) {
		return "", ErrDomainNotFound
	}

	passwdPath := filepath.Join(p.Config, domain, "passwd")

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return "", err
	}
	defer unlock()

	if !userExists(passwdPath, username) {
		return "", ErrUserNotFound
	}

	hadKeys := false
	if status := p.userKeyStatus(domain, username); status.Exists && status.HasPrivate {
		hadKeys = true
	}

	if err := passwd.SetPassword(passwdPath, username, newPassword); err != nil {
		return "", fmt.Errorf("update password: %w", err)
	}

	if !hadKeys {
		return "", nil
	}

	// Drop any legacy config-tree key so the regenerated keyring is the only
	// key present (DeleteUserKeys clears both locations).
	_ = keys.DeleteKeypair(p.domainKeysDir(domain), username)
	if _, err := p.createUserKeypair(domain, username, newPassword); err != nil {
		return "", fmt.Errorf("regenerate keypair (password already changed; old key is orphaned until this is fixed): %w", err)
	}
	if err := p.provisionDomainConfigTree(domain); err != nil {
		return "", fmt.Errorf("config ownership: %w", err)
	}
	status := p.userKeyStatus(domain, username)
	return status.Fingerprint, nil
}
