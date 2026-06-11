package admin

import (
	"regexp"
	"strings"
)

// MinPasswordLength is the minimum accepted password length.
const MinPasswordLength = 8

// domainNameRe validates domain names: lowercase alphanumeric, hyphens, dots.
var domainNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// usernameRe validates usernames: alphanumeric start, then dots, hyphens, underscores.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidDomainName reports whether name is a valid, path-safe domain name.
func ValidDomainName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return domainNameRe.MatchString(name)
}

// ValidUsername reports whether name is a valid, path-safe username.
func ValidUsername(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return usernameRe.MatchString(name)
}

// ValidPassword reports whether password meets minimum requirements.
func ValidPassword(password string) bool {
	return len(password) >= MinPasswordLength
}
