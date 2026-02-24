// Package middleware provides HTTP middleware for the webadmin server.
package middleware

import (
	"log/slog"
	"net/http"

	"github.com/infodancer/maildancer/internal/webadmin/audit"
	"github.com/infodancer/maildancer/internal/webadmin/rbac"
	"github.com/infodancer/maildancer/internal/webadmin/session"
)

// RequireAuth redirects unauthenticated requests to /login.
// It also injects the admin username into the request context for audit logging.
func RequireAuth(store *session.Store, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := store.Get(r)
			if sess == nil {
				logger.Debug("unauthenticated request, redirecting to login",
					slog.String("path", r.URL.Path),
					slog.String("remote", r.RemoteAddr))
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			ctx := audit.WithAdmin(r.Context(), sess.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireCSRF validates CSRF tokens on state-changing requests.
func RequireCSRF(store *session.Store, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate on state-changing methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			sess := store.Get(r)
			if sess == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			if !store.ValidateCSRF(r, sess) {
				logger.Warn("CSRF validation failed",
					slog.String("path", r.URL.Path),
					slog.String("remote", r.RemoteAddr),
					slog.String("user", sess.Username))
				http.Error(w, "Forbidden: CSRF validation failed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireDomainAccess checks that the authenticated user has RBAC access to the domain
// extracted from the named path value. If roles is nil, all access is allowed.
func RequireDomainAccess(store *session.Store, roles *rbac.RoleStore, domainParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if roles == nil {
				next.ServeHTTP(w, r)
				return
			}
			sess := store.Get(r)
			if sess == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			domain := r.PathValue(domainParam)
			if domain != "" && !roles.IsSuperAdmin(sess.Username) && !roles.CanAccessDomain(sess.Username, domain) {
				http.Error(w, "Forbidden: insufficient domain access", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSuperAdmin checks that the authenticated user has super_admin role.
// If roles is nil (no roles file configured), all authenticated users are allowed.
func RequireSuperAdmin(store *session.Store, roles *rbac.RoleStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if roles == nil {
				next.ServeHTTP(w, r)
				return
			}
			sess := store.Get(r)
			if sess == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if !roles.IsSuperAdmin(sess.Username) {
				http.Error(w, "Forbidden: super_admin required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders adds standard security headers to all responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return SecurityHeadersWithHSTS(false)(next)
}

// SecurityHeadersWithHSTS adds security headers, optionally including HSTS for TLS.
func SecurityHeadersWithHSTS(tlsEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// CSP: allows HTMX (unpkg), Chart.js and Pico CSS (jsdelivr), inline styles/scripts for templates
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "+
					"script-src 'self' https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"font-src 'self'")
			if tlsEnabled {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestLogger logs HTTP requests.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote", r.RemoteAddr))
			next.ServeHTTP(w, r)
		})
	}
}

// Chain applies middleware in order (first middleware is outermost).
func Chain(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
