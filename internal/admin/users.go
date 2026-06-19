package admin

import (
	"fmt"
	"path/filepath"

	domainpkg "github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/auth/identity"
	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/admin/keys"
)

// UserSummary describes a user for listings.
type UserSummary struct {
	Username string
	Mailbox  string
	UID      uint32
	HasKeys  bool
}

// CreateUserResult reports the outcome of CreateUser.
type CreateUserResult struct {
	UID           uint32
	KeysGenerated bool
	// Warnings holds non-fatal problems (e.g. maildir creation failure when
	// the passwd entry was already written). The user exists when err is nil.
	Warnings []string
}

// CreateUser validates inputs, allocates a uid, writes the passwd entry,
// creates the maildir directory in the data volume, and optionally generates
// an X25519 keypair encrypted with the user's password.
func (p Paths) CreateUser(domain, username, password string, generateKeys bool) (*CreateUserResult, error) {
	if !ValidDomainName(domain) {
		return nil, ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return nil, ErrInvalidUsername
	}
	if !ValidPassword(password) {
		return nil, fmt.Errorf("%w: minimum %d characters", ErrWeakPassword, MinPasswordLength)
	}
	if !p.DomainExists(domain) {
		return nil, ErrDomainNotFound
	}

	domainPath := filepath.Join(p.Config, domain)
	passwdPath := filepath.Join(domainPath, "passwd")

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return nil, err
	}

	if userExists(passwdPath, username) {
		unlock()
		return nil, ErrUserExists
	}

	// Identity allocation goes through the single identity code path, which
	// records the uid in {config}/{domain}/uid.toml. The passwd entry carries
	// only credentials (user:hash:mailbox) -- not the uid.
	uid, err := p.idMgr().AllocateUserUID(domain, username)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("allocate uid: %w", err)
	}

	if err := passwd.AddUser(passwdPath, username, password); err != nil {
		unlock()
		_ = p.idMgr().RemoveUser(domain, username)
		return nil, fmt.Errorf("write passwd: %w", err)
	}
	unlock()

	result := &CreateUserResult{UID: uid}

	// Create the user's data directory owned uid:gid 0700 (the security model),
	// so the privilege-separated mail-session can open its own maildir. Non-fatal:
	// the passwd entry is already durable and delivery creates maildirs on demand,
	// but a wrong owner here is the classic "permission denied" trap, so surface it.
	if err := p.provisionUserDataDir(domain, username, uid); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("create maildir: %v", err))
	}

	// Generate a keypair when explicitly requested, or by default when the
	// domain's encryption_mode is "on". The runtime encrypt gate is key
	// presence, so provisioning a key here is what turns on at-rest encryption
	// for this user (maildancer#65).
	if generateKeys || p.domainProvisionsKeys(domain) {
		if warns, err := p.createUserKeypair(domain, username, password); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("generate keys: %v", err))
		} else {
			result.KeysGenerated = true
			result.Warnings = append(result.Warnings, warns...)
		}
	}

	return result, nil
}

// domainProvisionsKeys reports whether the domain's encryption_mode is "on",
// so new users are provisioned an encryption keypair by default. A missing or
// unreadable config is treated as "off".
func (p Paths) domainProvisionsKeys(domain string) bool {
	cfg, err := domainpkg.LoadDomainConfig(filepath.Join(p.Config, domain, "config.toml"))
	if err != nil {
		return false
	}
	return cfg.ProvisionKeysByDefault()
}

// DeleteUser removes the user's passwd entry and any key files.
func (p Paths) DeleteUser(domain, username string) error {
	if !ValidDomainName(domain) {
		return ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	if !p.DomainExists(domain) {
		return ErrDomainNotFound
	}

	domainPath := filepath.Join(p.Config, domain)
	passwdPath := filepath.Join(domainPath, "passwd")

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return err
	}
	defer unlock()

	if !userExists(passwdPath, username) {
		return ErrUserNotFound
	}
	if err := passwd.DeleteUser(passwdPath, username); err != nil {
		return fmt.Errorf("remove passwd entry: %w", err)
	}
	// Release the uid allocation. Best-effort: the credential is already gone,
	// so a stale uid.toml entry would only be reclaimed by the next domain fix.
	_ = p.idMgr().RemoveUser(domain, username)

	// Key removal is best-effort, matching prior webadmin behavior. Remove the
	// data-tree keyring and any legacy config-tree key files.
	_ = keys.DeleteKeypair(p.userKeyringDir(domain, username), keyringName)
	_ = keys.DeleteKeypair(filepath.Join(domainPath, "keys"), username)

	return nil
}

// ResetPassword replaces the user's password hash, preserving mailbox and uid.
// Users with a sealed encryption key are refused with ErrUserHasKeys: a bare
// hash reset would orphan the key and lock the user out at the next login.
// Use ChangePassword (current password known) or ResetPasswordRegenKeys
// (explicit admin reset, regenerates the keypair).
func (p Paths) ResetPassword(domain, username, password string) error {
	if !ValidDomainName(domain) {
		return ErrInvalidDomainName
	}
	if !ValidUsername(username) {
		return ErrInvalidUsername
	}
	if !ValidPassword(password) {
		return fmt.Errorf("%w: minimum %d characters", ErrWeakPassword, MinPasswordLength)
	}
	if !p.DomainExists(domain) {
		return ErrDomainNotFound
	}

	passwdPath := filepath.Join(p.Config, domain, "passwd")

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return err
	}
	defer unlock()

	if !userExists(passwdPath, username) {
		return ErrUserNotFound
	}
	if status := p.userKeyStatus(domain, username); status.Exists && status.HasPrivate {
		return ErrUserHasKeys
	}
	if err := passwd.SetPassword(passwdPath, username, password); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

// ListUsers returns all users in a domain with key presence.
func (p Paths) ListUsers(domain string) ([]UserSummary, error) {
	if !ValidDomainName(domain) {
		return nil, ErrInvalidDomainName
	}
	if !p.DomainExists(domain) {
		return nil, ErrDomainNotFound
	}

	domainPath := filepath.Join(p.Config, domain)
	users, err := passwd.ListUsers(filepath.Join(domainPath, "passwd"))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	summaries := []UserSummary{}
	for _, u := range users {
		// UID is authoritative in uid.toml; 0 means not yet allocated.
		uid, err := identity.UserUID(p.Config, domain, u.Username)
		if err != nil {
			uid = 0
		}
		summaries = append(summaries, UserSummary{
			Username: u.Username,
			Mailbox:  u.Mailbox,
			UID:      uid,
			HasKeys:  p.userKeyStatus(domain, u.Username).Exists,
		})
	}
	return summaries, nil
}

// userExists reports whether the username has a passwd entry. A missing or
// unreadable passwd file reads as "no users".
func userExists(passwdPath, username string) bool {
	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		return false
	}
	for _, u := range users {
		if u.Username == username {
			return true
		}
	}
	return false
}
