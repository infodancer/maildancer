package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infodancer/maildancer/internal/webadmin/session"
)

func newTestUserHandler(t *testing.T) (*UserHandler, string) {
	t.Helper()
	dir := t.TempDir()
	store := session.NewStore(30 * time.Minute)
	return NewUserHandler(dir, store, slog.Default()), dir
}

func TestHandleListUsers_Empty(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	// Overwrite with empty passwd
	os.WriteFile(filepath.Join(dir, "example.com", "passwd"), []byte("# Users\n"), 0o640)

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/users", nil)
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleListUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var users []UserSummary
	json.NewDecoder(rr.Body).Decode(&users)
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

func TestHandleListUsers_WithUsers(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/users", nil)
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleListUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var users []UserSummary
	json.NewDecoder(rr.Body).Decode(&users)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "user1" {
		t.Errorf("expected username user1, got %s", users[0].Username)
	}
}

func TestHandleCreateUser(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]any{
		"username": "newuser",
		"password": "strongpassword123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/example.com/users", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleCreateUser(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify user appears in passwd
	passwdPath := filepath.Join(dir, "example.com", "passwd")
	if !userExistsInPasswd(passwdPath, "newuser") {
		t.Error("expected newuser in passwd file")
	}
}

func TestHandleCreateUser_WithKeys(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]any{
		"username":      "keyuser",
		"password":      "strongpassword123",
		"generate_keys": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/example.com/users", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleCreateUser(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify keys were created
	keysDir := filepath.Join(dir, "example.com", "keys")
	if _, err := os.Stat(filepath.Join(keysDir, "keyuser.pub")); err != nil {
		t.Error("expected public key file")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "keyuser.key")); err != nil {
		t.Error("expected private key file")
	}
}

func TestHandleCreateUser_AlreadyExists(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]string{
		"username": "user1",
		"password": "strongpassword123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/example.com/users", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleCreateUser(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestHandleCreateUser_WeakPassword(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]string{
		"username": "newuser",
		"password": "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/example.com/users", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleCreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCreateUser_InvalidUsername(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]string{
		"username": "../escape",
		"password": "strongpassword123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/example.com/users", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	rr := httptest.NewRecorder()
	h.HandleCreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleDeleteUser(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com/users/user1", nil)
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleDeleteUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	passwdPath := filepath.Join(dir, "example.com", "passwd")
	if userExistsInPasswd(passwdPath, "user1") {
		t.Error("expected user1 removed from passwd")
	}
}

func TestHandleDeleteUser_NotFound(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com/users/missing", nil)
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "missing")
	rr := httptest.NewRecorder()
	h.HandleDeleteUser(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleResetPassword(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	body, _ := json.Marshal(map[string]string{"password": "newstrongpassword"})
	req := httptest.NewRequest(http.MethodPut, "/api/domains/example.com/users/user1/password", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleResetPassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify hash was updated (not the old "hash1")
	data, _ := os.ReadFile(filepath.Join(dir, "example.com", "passwd"))
	if strings.Contains(string(data), "hash1") {
		t.Error("expected old hash to be replaced")
	}
	if !strings.Contains(string(data), "$argon2id$") {
		t.Error("expected argon2id hash in passwd")
	}
}

func TestHandleGetKeys(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/domains/example.com/users/user1/keys", nil)
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleGetKeys(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var result map[string]any
	json.NewDecoder(rr.Body).Decode(&result)
	if result["encryption_enabled"] != false {
		t.Error("expected encryption_enabled=false without keys")
	}
}

func TestHandleCreateAndDeleteKeys(t *testing.T) {
	h, dir := newTestUserHandler(t)
	createTestDomain(t, dir, "example.com")

	// Create keys
	body, _ := json.Marshal(map[string]string{"password": "strongpassword123"})
	req := httptest.NewRequest(http.MethodPost, "/api/domains/example.com/users/user1/keys", bytes.NewReader(body))
	req.SetPathValue("domain", "example.com")
	req.SetPathValue("username", "user1")
	rr := httptest.NewRecorder()
	h.HandleCreateKeys(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify keys exist
	keysDir := filepath.Join(dir, "example.com", "keys")
	if _, err := os.Stat(filepath.Join(keysDir, "user1.pub")); err != nil {
		t.Error("expected public key")
	}

	// Delete keys
	delReq := httptest.NewRequest(http.MethodDelete, "/api/domains/example.com/users/user1/keys", nil)
	delReq.SetPathValue("domain", "example.com")
	delReq.SetPathValue("username", "user1")
	delRR := httptest.NewRecorder()
	h.HandleDeleteKeys(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", delRR.Code)
	}

	if _, err := os.Stat(filepath.Join(keysDir, "user1.pub")); err == nil {
		t.Error("expected public key to be removed")
	}
}

func TestIsValidUsername(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"alice", true},
		{"bob.smith", true},
		{"user-name", true},
		{"user_name", true},
		{"User123", true},
		{"", false},
		{"../escape", false},
		{"/etc", false},
		{".hidden", false},
		{"-start", false},
		{"a b", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidUsername(tt.name); got != tt.valid {
				t.Errorf("isValidUsername(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword("testpassword")
	if err != nil {
		t.Fatalf("hashPassword() error: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("expected argon2id prefix, got %q", hash[:20])
	}
}
