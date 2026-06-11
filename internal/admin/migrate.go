package admin

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"

	"github.com/infodancer/maildancer/auth/passwd"
	"github.com/infodancer/maildancer/internal/admin/uidalloc"
)

// MigrateResult summarizes a MigrateUIDs run.
type MigrateResult struct {
	DomainsMigrated int
	UsersMigrated   int
	// Details records each allocation as "domain gid=N" or "user@domain uid=N".
	Details []string
	// Errors collects per-domain failures; migration continues past them.
	Errors []string
}

// MigrateUIDs walks every domain, allocating a gid for domains without one
// and a uid for passwd entries without one. Per-domain failures are recorded
// in the result rather than aborting the walk.
func (p Paths) MigrateUIDs() (*MigrateResult, error) {
	result := &MigrateResult{Details: []string{}, Errors: []string{}}

	entries, err := os.ReadDir(p.Config)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, fmt.Errorf("read domains directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] == '.' {
			continue
		}
		name := entry.Name()

		domainMigrated, usersMigrated, details, errs := p.migrateDomain(name)
		if domainMigrated {
			result.DomainsMigrated++
		}
		result.UsersMigrated += usersMigrated
		result.Details = append(result.Details, details...)
		result.Errors = append(result.Errors, errs...)
	}

	return result, nil
}

// migrateDomain ensures one domain has a gid and all its users have uids.
func (p Paths) migrateDomain(name string) (domainMigrated bool, usersMigrated int, details, errs []string) {
	// Gid lives in the data volume config.toml.
	dataDir := filepath.Join(p.Data, name)
	dataConfigPath := filepath.Join(dataDir, "config.toml")

	var gid uint32
	if data, err := os.ReadFile(dataConfigPath); err == nil {
		var cfg dataVolumeConfig
		if err := toml.Unmarshal(data, &cfg); err == nil {
			gid = cfg.Domain.Gid
		}
	}

	if gid == 0 {
		allocated, err := uidalloc.Allocate(p.Data)
		if err != nil {
			return false, 0, details, append(errs, fmt.Sprintf("%s: allocate gid: %v", name, err))
		}
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			return false, 0, details, append(errs, fmt.Sprintf("%s: create data dir: %v", name, err))
		}
		dataConfig := fmt.Sprintf("[domain]\ngid = %d\n", allocated)
		if err := os.WriteFile(dataConfigPath, []byte(dataConfig), 0o640); err != nil {
			return false, 0, details, append(errs, fmt.Sprintf("%s: write data config.toml: %v", name, err))
		}
		domainMigrated = true
		details = append(details, fmt.Sprintf("%s gid=%d", name, allocated))
	}

	migrated, userDetails, err := p.migratePasswdUIDs(name)
	if err != nil {
		errs = append(errs, fmt.Sprintf("%s: migrate passwd: %v", name, err))
	}
	return domainMigrated, migrated, append(details, userDetails...), errs
}

// migratePasswdUIDs allocates uids for passwd entries that lack one.
func (p Paths) migratePasswdUIDs(domain string) (int, []string, error) {
	passwdPath := filepath.Join(p.Config, domain, "passwd")

	users, err := passwd.ListUsers(passwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil, nil
		}
		return 0, nil, err
	}

	var needsUID []string
	for _, u := range users {
		if u.Uid == 0 {
			needsUID = append(needsUID, u.Username)
		}
	}
	if len(needsUID) == 0 {
		return 0, nil, nil
	}

	unlock, err := p.lockDomain(domain)
	if err != nil {
		return 0, nil, err
	}
	defer unlock()

	migrated := 0
	var details []string
	for _, username := range needsUID {
		uid, err := uidalloc.Allocate(p.Data)
		if err != nil {
			return migrated, details, fmt.Errorf("allocate uid for %s: %w", username, err)
		}
		if err := passwd.SetUID(passwdPath, username, uid); err != nil {
			return migrated, details, fmt.Errorf("set uid for %s: %w", username, err)
		}
		migrated++
		details = append(details, fmt.Sprintf("%s@%s uid=%d", username, domain, uid))
	}
	return migrated, details, nil
}
