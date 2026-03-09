package domain

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// PostmasterEntry holds the domain-level identity record from the postmaster file.
// It provides the authoritative GID and data path for a domain.
type PostmasterEntry struct {
	Address  string // "postmaster" or "postmaster@example.com"
	UID      uint32
	GID      uint32
	DataPath string // absolute path to the domain's data directory
	Domain   string // empty string for the system postmaster
}

// ParsePostmasterFile reads a postmaster file and returns entries keyed by
// domain name. The system postmaster (address without @domain) is stored under
// the empty string key. Lines beginning with '#' and blank lines are ignored.
//
// Format (four colon-separated fields):
//
//	postmaster:10001:10001:/var/mail
//	postmaster@example.com:10013:10014:/opt/infodancer/domains/example.com
func ParsePostmasterFile(path string) (map[string]*PostmasterEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	entries := make(map[string]*PostmasterEntry)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("line %d: expected 4 colon-separated fields, got %d", lineNum, len(parts))
		}
		address := parts[0]
		uid64, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid uid %q: %w", lineNum, parts[1], err)
		}
		gid64, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid gid %q: %w", lineNum, parts[2], err)
		}
		dataPath := parts[3]

		var domainName string
		if idx := strings.Index(address, "@"); idx >= 0 {
			domainName = strings.ToLower(address[idx+1:])
		}

		entries[domainName] = &PostmasterEntry{
			Address:  address,
			UID:      uint32(uid64),
			GID:      uint32(gid64),
			DataPath: dataPath,
			Domain:   domainName,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return entries, nil
}

// LookupDomainPostmaster returns the PostmasterEntry for the given domain from
// {domainsPath}/postmaster. Returns nil if the file does not exist or the
// domain has no entry — the caller should fall back to other config sources.
func LookupDomainPostmaster(domainsPath, domainName string) *PostmasterEntry {
	entries, err := ParsePostmasterFile(filepath.Join(domainsPath, "postmaster"))
	if err != nil {
		return nil
	}
	return entries[strings.ToLower(domainName)]
}
