package passwd

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// UserInfo holds the display fields for a user entry.
type UserInfo struct {
	Username string
	Mailbox  string
}

// HashPassword generates an argon2id hash of password using canonical parameters.
// The returned string is the full PHC-format hash ready to embed in a passwd entry.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads, encodedSalt, encodedHash), nil
}

// AddUser appends a new user entry to the passwd file at passwdPath.
// Returns an error if the username already exists.
func AddUser(passwdPath, username, password string) error {
	users, err := parsePasswd(passwdPath)
	if err != nil {
		return err
	}

	for _, u := range users {
		if u.Username == username {
			return fmt.Errorf("user %q already exists", username)
		}
	}

	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(passwdPath, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open passwd file: %w", err)
	}
	defer func() { _ = f.Close() }()

	_, err = fmt.Fprintf(f, "%s:%s:%s\n", username, hash, username)
	return err
}

// DeleteUser removes the named user from the passwd file.
// Returns an error if the user does not exist.
func DeleteUser(passwdPath, username string) error {
	lines, found, err := filterPasswd(passwdPath, username)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("user %q not found", username)
	}
	return writePasswd(passwdPath, lines)
}

// ListUsers returns all user entries from the passwd file.
func ListUsers(passwdPath string) ([]UserInfo, error) {
	return parsePasswd(passwdPath)
}

// parsePasswd reads the passwd file and returns all user entries.
func parsePasswd(passwdPath string) ([]UserInfo, error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("open passwd file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var users []UserInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		mailbox := parts[0]
		if len(parts) >= 3 {
			mailbox = parts[2]
		}
		users = append(users, UserInfo{Username: parts[0], Mailbox: mailbox})
	}

	return users, scanner.Err()
}

// filterPasswd reads all lines from the passwd file, returning them with the
// named user removed. found reports whether the user was present.
func filterPasswd(passwdPath, username string) (lines []string, found bool, err error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, false, fmt.Errorf("open passwd file: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 3)
		if len(parts) >= 1 && parts[0] == username {
			found = true
			continue
		}
		lines = append(lines, line)
	}

	return lines, found, scanner.Err()
}

// writePasswd atomically replaces the passwd file with the given lines.
func writePasswd(passwdPath string, lines []string) error {
	tmpPath := passwdPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("create temp passwd file: %w", err)
	}

	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}

	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, passwdPath)
}
