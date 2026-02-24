package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

const (
	// Argon2id parameters matching auth/passwd
	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32

	// Key encryption constants matching auth/passwd
	saltSize  = 32
	nonceSize = 24

	minPasswordLength = 8
)

// usernameRe validates usernames: alphanumeric, dots, hyphens, underscores.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// UserHandler handles user management API requests.
type UserHandler struct {
	domainsPath string
	sessions    *session.Store
	logger      *slog.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(domainsPath string, sessions *session.Store, logger *slog.Logger) *UserHandler {
	return &UserHandler{
		domainsPath: domainsPath,
		sessions:    sessions,
		logger:      logger,
	}
}

// UserSummary is the JSON representation of a user.
type UserSummary struct {
	Username          string `json:"username"`
	Mailbox           string `json:"mailbox"`
	EncryptionEnabled bool   `json:"encryption_enabled"`
}

// HandleListUsers returns a JSON list of users in a domain.
func (h *UserHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	users, err := h.listUsers(domainPath)
	if err != nil {
		h.logger.Error("failed to list users", "domain", domain, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
		return
	}

	writeJSON(w, http.StatusOK, users)
}

// HandleCreateUser creates a new user in a domain.
func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		GenerateKeys bool   `json:"generate_keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if !isValidUsername(req.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid username"})
		return
	}
	if !isStrongPassword(req.Password) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("password must be at least %d characters", minPasswordLength),
		})
		return
	}

	passwdPath := filepath.Join(domainPath, "passwd")
	if userExistsInPasswd(passwdPath, req.Username) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "user already exists"})
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		h.logger.Error("failed to hash password", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	line := fmt.Sprintf("%s:%s:%s\n", req.Username, hash, req.Username)
	if err := appendToFile(passwdPath, line); err != nil {
		h.logger.Error("failed to write passwd", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
	}

	if req.GenerateKeys {
		keysDir := filepath.Join(domainPath, "keys")
		if err := generateUserKeys(keysDir, req.Username, req.Password); err != nil {
			h.logger.Error("failed to generate keys", "user", req.Username, "error", err)
			// User was created but key generation failed - log but don't fail
		}
	}

	h.logAudit(r, "user_created", slog.String("domain", domain), slog.String("user", req.Username))
	writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username, "status": "created"})
}

// HandleDeleteUser removes a user from a domain.
func (h *UserHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid username"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	if !dirExists(domainPath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	passwdPath := filepath.Join(domainPath, "passwd")
	if !userExistsInPasswd(passwdPath, username) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	if err := removeUserFromPasswd(passwdPath, username); err != nil {
		h.logger.Error("failed to remove user from passwd", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete user"})
		return
	}

	// Remove key files if they exist
	keysDir := filepath.Join(domainPath, "keys")
	_ = os.Remove(filepath.Join(keysDir, username+".pub"))
	_ = os.Remove(filepath.Join(keysDir, username+".key"))

	h.logAudit(r, "user_deleted", slog.String("domain", domain), slog.String("user", username))
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "deleted"})
}

// HandleResetPassword changes a user's password.
func (h *UserHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	passwdPath := filepath.Join(domainPath, "passwd")

	if !dirExists(domainPath) || !userExistsInPasswd(passwdPath, username) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if !isStrongPassword(req.Password) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("password must be at least %d characters", minPasswordLength),
		})
		return
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		h.logger.Error("failed to hash password", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := updatePasswordInPasswd(passwdPath, username, hash); err != nil {
		h.logger.Error("failed to update password", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
		return
	}

	h.logAudit(r, "password_reset", slog.String("domain", domain), slog.String("user", username))
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "password_updated"})
}

// HandleGetKeys returns encryption key status for a user.
func (h *UserHandler) HandleGetKeys(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	keysDir := filepath.Join(domainPath, "keys")

	pubKeyPath := filepath.Join(keysDir, username+".pub")
	privKeyPath := filepath.Join(keysDir, username+".key")

	_, pubErr := os.Stat(pubKeyPath)
	_, privErr := os.Stat(privKeyPath)
	hasKeys := pubErr == nil && privErr == nil

	writeJSON(w, http.StatusOK, map[string]any{
		"username":           username,
		"encryption_enabled": hasKeys,
		"has_public_key":     pubErr == nil,
	})
}

// HandleCreateKeys generates a new keypair for a user.
func (h *UserHandler) HandleCreateKeys(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required to encrypt the private key"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	keysDir := filepath.Join(domainPath, "keys")

	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create keys directory"})
		return
	}

	if err := generateUserKeys(keysDir, username, req.Password); err != nil {
		h.logger.Error("failed to generate keys", "user", username, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate keys"})
		return
	}

	h.logAudit(r, "keys_generated", slog.String("domain", domain), slog.String("user", username))
	writeJSON(w, http.StatusCreated, map[string]string{"username": username, "status": "keys_generated"})
}

// HandleDeleteKeys removes encryption keys for a user.
func (h *UserHandler) HandleDeleteKeys(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	username := r.PathValue("username")

	if !isValidDomainName(domain) || !isValidUsername(username) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain or username"})
		return
	}

	domainPath := filepath.Join(h.domainsPath, domain)
	keysDir := filepath.Join(domainPath, "keys")

	pubKeyPath := filepath.Join(keysDir, username+".pub")
	privKeyPath := filepath.Join(keysDir, username+".key")

	_ = os.Remove(pubKeyPath)
	_ = os.Remove(privKeyPath)

	h.logAudit(r, "keys_removed", slog.String("domain", domain), slog.String("user", username))
	writeJSON(w, http.StatusOK, map[string]string{"username": username, "status": "keys_removed"})
}

// logAudit logs an audit event with admin username and remote IP.
func (h *UserHandler) logAudit(r *http.Request, action string, attrs ...slog.Attr) {
	sess := h.sessions.Get(r)
	admin := ""
	if sess != nil {
		admin = sess.Username
	}
	allAttrs := append([]slog.Attr{
		slog.String("action", action),
		slog.String("admin", admin),
		slog.String("remote", r.RemoteAddr),
	}, attrs...)

	args := make([]any, len(allAttrs))
	for i, a := range allAttrs {
		args[i] = a
	}
	h.logger.Info("audit", args...)
}

// listUsers reads the passwd file and checks for key files.
func (h *UserHandler) listUsers(domainPath string) ([]UserSummary, error) {
	passwdPath := filepath.Join(domainPath, "passwd")
	data, err := os.ReadFile(passwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []UserSummary{}, nil
		}
		return nil, fmt.Errorf("read passwd: %w", err)
	}

	keysDir := filepath.Join(domainPath, "keys")
	var users []UserSummary

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		username := parts[0]
		mailbox := username
		if len(parts) >= 3 {
			mailbox = parts[2]
		}

		pubKeyPath := filepath.Join(keysDir, username+".pub")
		_, pubErr := os.Stat(pubKeyPath)

		users = append(users, UserSummary{
			Username:          username,
			Mailbox:           mailbox,
			EncryptionEnabled: pubErr == nil,
		})
	}

	if users == nil {
		users = []UserSummary{}
	}
	return users, nil
}

// isValidUsername checks that the username is safe.
func isValidUsername(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return usernameRe.MatchString(name)
}

// isStrongPassword checks minimum password requirements.
func isStrongPassword(password string) bool {
	return len(password) >= minPasswordLength
}

// hashPassword generates an argon2id hash in the same format as auth/passwd.
func hashPassword(password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// userExistsInPasswd checks if a username exists in the passwd file.
func userExistsInPasswd(path, username string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if parts[0] == username {
			return true
		}
	}
	return false
}

// removeUserFromPasswd removes a user line from the passwd file.
func removeUserFromPasswd(path, username string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read passwd: %w", err)
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if parts[0] != username {
			lines = append(lines, line)
		}
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o640)
}

// updatePasswordInPasswd updates the hash for a user in the passwd file.
func updatePasswordInPasswd(path, username, newHash string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read passwd: %w", err)
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 3)
		if parts[0] == username {
			mailbox := username
			if len(parts) >= 3 {
				mailbox = parts[2]
			}
			lines = append(lines, fmt.Sprintf("%s:%s:%s", username, newHash, mailbox))
		} else {
			lines = append(lines, line)
		}
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o640)
}

// appendToFile appends text to a file.
func appendToFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(text)
	return err
}

// generateUserKeys generates a NaCl box keypair and stores it.
// The private key is encrypted with the user's password using the same
// format as auth/passwd: salt (32B) || nonce (24B) || ciphertext.
func generateUserKeys(keysDir, username, password string) error {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	// Write public key
	pubKeyPath := filepath.Join(keysDir, username+".pub")
	if err := os.WriteFile(pubKeyPath, pubKey[:], 0o640); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	// Encrypt private key with password
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	var key [32]byte
	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	copy(key[:], derivedKey)

	encrypted := secretbox.Seal(nil, privKey[:], &nonce, &key)

	// Format: salt || nonce || ciphertext
	encryptedKey := make([]byte, 0, saltSize+nonceSize+len(encrypted))
	encryptedKey = append(encryptedKey, salt...)
	encryptedKey = append(encryptedKey, nonce[:]...)
	encryptedKey = append(encryptedKey, encrypted...)

	privKeyPath := filepath.Join(keysDir, username+".key")
	if err := os.WriteFile(privKeyPath, encryptedKey, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	return nil
}
