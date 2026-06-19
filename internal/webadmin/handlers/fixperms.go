package handlers

import (
	"fmt"
	"net/http"
	"os"

	"github.com/infodancer/maildancer/internal/admin"
)

// permResultJSON is the per-path outcome of a permission fix, JSON-shaped.
type permResultJSON struct {
	Path    string `json:"path"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Mode    string `json:"mode"`
	Changed bool   `json:"changed"`
	Skipped bool   `json:"skipped"`
	Error   string `json:"error,omitempty"`
}

// fixPermsResponse is the JSON returned by the fix-perms endpoint. It mirrors
// the admin.PermReport plus a derived off-root caveat so the UI can tell the
// operator when ownership changes could not be applied.
type fixPermsResponse struct {
	Domain string `json:"domain"`
	// RunningAsRoot reports whether webadmin can apply ownership (chown). When
	// false, ownership entries are reported as skipped and only modes are set.
	RunningAsRoot    bool             `json:"running_as_root"`
	OwnershipSkipped bool             `json:"ownership_skipped"`
	Allocated        []string         `json:"allocated"`
	Warnings         []string         `json:"warnings"`
	Entries          []permResultJSON `json:"entries"`
	ChangedCount     int              `json:"changed_count"`
	ErrorCount       int              `json:"error_count"`
}

// HandleFixPerms repairs a domain's data-tree ownership and modes against the
// mail security model (data/{domain} + users/ = root:{gid} 2750; users/{user} =
// {uid}:{gid} 0700), allocating any missing ids first. It delegates to the
// shared admin.Paths.FixDomain -- the same operation behind `userctl domain fix`
// -- and renders the resulting report.
//
// Ownership (chown) requires root. When webadmin runs unprivileged it can only
// set modes; affected entries come back marked skipped and the response sets
// ownership_skipped so the caller knows the tree was not fully repaired.
func (h *DomainHandler) HandleFixPerms(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !isValidDomainName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain name"})
		return
	}
	if err := h.checkDomainAccess(r, name); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if !h.ops.DomainExists(name) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}

	report, err := h.ops.FixDomain(name)
	// FixDomain returns a populated report alongside a per-path error when some
	// paths could not be fully fixed; that is a 200 with error_count > 0. Only a
	// hard failure that produced no plan (e.g. id allocation failed) is a 500.
	if err != nil && len(report.Entries) == 0 {
		h.logger.Error("fix-perms failed", "domain", name, "error", err)
		h.logAudit(r, "fix_perms", name, "failure", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fix permissions"})
		return
	}

	resp := buildFixPermsResponse(name, report)

	result := "success"
	if resp.ErrorCount > 0 {
		result = "partial"
	}
	h.logAudit(r, "fix_perms", name, result,
		fmt.Sprintf("changed=%d errors=%d allocated=%d ownership_skipped=%t",
			resp.ChangedCount, resp.ErrorCount, len(resp.Allocated), resp.OwnershipSkipped))

	writeJSON(w, http.StatusOK, resp)
}

// buildFixPermsResponse converts an admin.PermReport into the JSON response,
// deriving the changed/error counts and the off-root ownership caveat.
func buildFixPermsResponse(domain string, report admin.PermReport) fixPermsResponse {
	resp := fixPermsResponse{
		Domain:        domain,
		RunningAsRoot: os.Geteuid() == 0,
		Allocated:     report.Allocated,
		Warnings:      report.Warnings,
		Entries:       make([]permResultJSON, 0, len(report.Entries)),
	}
	for _, e := range report.Entries {
		if e.Changed {
			resp.ChangedCount++
		}
		if e.Err != "" {
			resp.ErrorCount++
		}
		if e.Skipped {
			resp.OwnershipSkipped = true
		}
		resp.Entries = append(resp.Entries, permResultJSON{
			Path:    e.Path,
			UID:     e.UID,
			GID:     e.GID,
			Mode:    unixMode(e.Mode),
			Changed: e.Changed,
			Skipped: e.Skipped,
			Error:   e.Err,
		})
	}
	return resp
}

// unixMode renders a Go FileMode as a traditional 4-digit octal string,
// including the setuid/setgid/sticky bits (e.g. sharedDirMode -> "2750").
func unixMode(m os.FileMode) string {
	o := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		o |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		o |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		o |= 0o1000
	}
	return fmt.Sprintf("%04o", o)
}
