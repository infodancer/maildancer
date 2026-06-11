package admin

import (
	"strings"
	"testing"
)

func TestPatchSectionValue_TopLevel(t *testing.T) {
	base := "# domain config\nmax_message_size = 1000\n\n[auth]\ntype = \"passwd\"\n"

	// Update an existing top-level key.
	out := string(PatchSectionValue([]byte(base), "", "max_message_size", "2000"))
	if !strings.Contains(out, "max_message_size = 2000") {
		t.Errorf("update failed:\n%s", out)
	}
	if !strings.Contains(out, "[auth]") || !strings.Contains(out, "# domain config") {
		t.Errorf("unrelated content lost:\n%s", out)
	}

	// Insert a new top-level key before the first section.
	out = string(PatchSectionValue([]byte(base), "", "recipient_rejection", QuoteString("data")))
	idx := strings.Index(out, "recipient_rejection = \"data\"")
	authIdx := strings.Index(out, "[auth]")
	if idx < 0 || authIdx < 0 || idx > authIdx {
		t.Errorf("insert misplaced (key at %d, [auth] at %d):\n%s", idx, authIdx, out)
	}

	// Remove a top-level key.
	out = string(PatchSectionValue([]byte(base), "", "max_message_size", ""))
	if strings.Contains(out, "max_message_size") {
		t.Errorf("remove failed:\n%s", out)
	}

	// Insert into a file with no sections at all.
	out = string(PatchSectionValue([]byte("# only comments\n"), "", "max_message_size", "5"))
	if !strings.Contains(out, "max_message_size = 5") || !strings.Contains(out, "# only comments") {
		t.Errorf("sectionless insert failed:\n%s", out)
	}

	// Insert into an empty file.
	out = string(PatchSectionValue(nil, "", "max_message_size", "5"))
	if strings.TrimSpace(out) != "max_message_size = 5" {
		t.Errorf("empty-file insert = %q", out)
	}

	// Removing a missing key is a no-op.
	out = string(PatchSectionValue([]byte(base), "", "nonexistent", ""))
	if out != base {
		t.Errorf("no-op changed content:\n%s", out)
	}
}

func TestPatchSectionValue_Sectioned(t *testing.T) {
	base := "[auth]\ntype = \"passwd\"\n\n[outbound]\nstrategy = \"direct\"\n"

	// Update within a section without touching siblings.
	out := string(PatchSectionValue([]byte(base), "outbound", "strategy", QuoteString("smarthost")))
	if !strings.Contains(out, "strategy = \"smarthost\"") || !strings.Contains(out, "type = \"passwd\"") {
		t.Errorf("sectioned update failed:\n%s", out)
	}

	// Append a missing section.
	out = string(PatchSectionValue([]byte(base), "limits", "max_sends_per_hour", "100"))
	if !strings.Contains(out, "[limits]\nmax_sends_per_hour = 100") {
		t.Errorf("section append failed:\n%s", out)
	}
}
