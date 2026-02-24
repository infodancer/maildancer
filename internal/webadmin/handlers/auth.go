// Package handlers provides HTTP request handlers for the webadmin.
package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// AuthHandler handles login and logout requests.
type AuthHandler struct {
	authAgent auth.AuthenticationAgent
	sessions  *session.Store
	logger    *slog.Logger
}

// NewAuthHandler creates a new authentication handler.
func NewAuthHandler(agent auth.AuthenticationAgent, sessions *session.Store, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		authAgent: agent,
		sessions:  sessions,
		logger:    logger,
	}
}

// HandleLoginPage renders the login form.
func (h *AuthHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to dashboard
	if sess := h.sessions.Get(r); sess != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	writeLoginPage(w, "", "")
}

// HandleLogin processes login form submissions.
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeLoginPage(w, "", "Invalid form submission")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		writeLoginPage(w, username, "Username and password are required")
		return
	}

	_, err := h.authAgent.Authenticate(context.Background(), username, password)
	if err != nil {
		h.logger.Warn("failed login attempt",
			slog.String("username", username),
			slog.String("remote", r.RemoteAddr))
		writeLoginPage(w, username, "Invalid username or password")
		return
	}

	sess, err := h.sessions.Create(w, username)
	if err != nil {
		h.logger.Error("failed to create session", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("admin login",
		slog.String("username", username),
		slog.String("remote", r.RemoteAddr),
		slog.String("session", sess.ID[:8]+"..."))

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleLogout clears the session and redirects to login.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	sess := h.sessions.Get(r)
	if sess != nil {
		h.logger.Info("admin logout",
			slog.String("username", sess.Username),
			slog.String("remote", r.RemoteAddr))
	}
	h.sessions.Destroy(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// writeLoginPage renders a minimal login page.
func writeLoginPage(w http.ResponseWriter, username, errorMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	errHTML := ""
	if errorMsg != "" {
		errHTML = `<p style="color: var(--pico-del-color);">` + errorMsg + `</p>`
	}

	// Minimal login page using Pico CSS
	page := `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mail Admin - Login</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
</head>
<body>
  <main class="container" style="max-width: 400px; margin-top: 10vh;">
    <article>
      <header>
        <h2>Mail Admin</h2>
      </header>
      ` + errHTML + `
      <form method="post" action="/login">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" value="` + username + `" required autofocus>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Log In</button>
      </form>
    </article>
  </main>
</body>
</html>`

	_, _ = w.Write([]byte(page))
}
