package config_test

import (
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/webadmin/config"
)

const configWithRspamd = `# Mail server configuration

[server]
hostname = "mail.example.com"

[spamcheck]
enabled = true
mode = "first_reject"

[[spamcheck.checkers]]
type = "rspamd"
url = "http://localhost:11334"
password = "old-secret"
timeout = "10s"
`

func TestPatchRspamdChecker_UpdateURL(t *testing.T) {
	result := config.PatchRspamdChecker([]byte(configWithRspamd), "http://rspamd.example.com:11334", "old-secret")
	s := string(result)

	if !strings.Contains(s, `url = "http://rspamd.example.com:11334"`) {
		t.Errorf("expected updated url, got:\n%s", s)
	}
	if strings.Contains(s, `url = "http://localhost:11334"`) {
		t.Errorf("expected old url replaced, got:\n%s", s)
	}
	if !strings.Contains(s, "# Mail server configuration") {
		t.Errorf("expected top comment preserved, got:\n%s", s)
	}
	if !strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected [server] section preserved, got:\n%s", s)
	}
	if !strings.Contains(s, `timeout = "10s"`) {
		t.Errorf("expected timeout line preserved, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_UpdatePassword(t *testing.T) {
	result := config.PatchRspamdChecker([]byte(configWithRspamd), "http://localhost:11334", "new-secret")
	s := string(result)

	if !strings.Contains(s, `password = "new-secret"`) {
		t.Errorf("expected updated password, got:\n%s", s)
	}
	if strings.Contains(s, `password = "old-secret"`) {
		t.Errorf("expected old password replaced, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_EmptyPasswordRemovesLine(t *testing.T) {
	result := config.PatchRspamdChecker([]byte(configWithRspamd), "http://localhost:11334", "")
	s := string(result)

	if strings.Contains(s, `password = "old-secret"`) {
		t.Errorf("expected password line removed, got:\n%s", s)
	}
	if strings.Contains(s, `password = ""`) {
		t.Errorf("expected no empty password line, got:\n%s", s)
	}
	// Other content preserved
	if !strings.Contains(s, `url = "http://localhost:11334"`) {
		t.Errorf("expected url preserved, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_PreservesOtherChecker(t *testing.T) {
	input := `[spamcheck]
enabled = true

[[spamcheck.checkers]]
type = "rspamd"
url = "http://localhost:11334"
password = "secret"

[[spamcheck.checkers]]
type = "other"
url = "http://other:8080"
`
	result := config.PatchRspamdChecker([]byte(input), "http://new:11334", "new-pass")
	s := string(result)

	// Other checker unchanged
	if !strings.Contains(s, `type = "other"`) {
		t.Errorf("expected other checker type preserved, got:\n%s", s)
	}
	if !strings.Contains(s, `url = "http://other:8080"`) {
		t.Errorf("expected other checker url preserved, got:\n%s", s)
	}
	// Rspamd updated
	if !strings.Contains(s, `url = "http://new:11334"`) {
		t.Errorf("expected rspamd url updated, got:\n%s", s)
	}
	if !strings.Contains(s, `password = "new-pass"`) {
		t.Errorf("expected rspamd password updated, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_MultipleCheckers_PatchesCorrectOne(t *testing.T) {
	input := `[[spamcheck.checkers]]
type = "other"
url = "http://other:1234"

[[spamcheck.checkers]]
type = "rspamd"
url = "http://localhost:11334"
password = "old"
`
	result := config.PatchRspamdChecker([]byte(input), "http://rspamd.new:11334", "new-pass")
	s := string(result)

	if !strings.Contains(s, `url = "http://other:1234"`) {
		t.Errorf("expected other checker url unchanged, got:\n%s", s)
	}
	if !strings.Contains(s, `url = "http://rspamd.new:11334"`) {
		t.Errorf("expected rspamd url updated, got:\n%s", s)
	}
	if strings.Contains(s, `url = "http://localhost:11334"`) {
		t.Errorf("expected old rspamd url replaced, got:\n%s", s)
	}
	if !strings.Contains(s, `password = "new-pass"`) {
		t.Errorf("expected rspamd password updated, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_NoBlock_AppendsNew(t *testing.T) {
	input := `[server]
hostname = "mail.example.com"

[spamcheck]
enabled = false
`
	result := config.PatchRspamdChecker([]byte(input), "http://rspamd:11334", "secret")
	s := string(result)

	if !strings.Contains(s, "[[spamcheck.checkers]]") {
		t.Errorf("expected [[spamcheck.checkers]] appended, got:\n%s", s)
	}
	if !strings.Contains(s, `type = "rspamd"`) {
		t.Errorf("expected type = rspamd appended, got:\n%s", s)
	}
	if !strings.Contains(s, `url = "http://rspamd:11334"`) {
		t.Errorf("expected url appended, got:\n%s", s)
	}
	if !strings.Contains(s, `password = "secret"`) {
		t.Errorf("expected password appended, got:\n%s", s)
	}
	// Original content preserved
	if !strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected original content preserved, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_NoBlock_NoPassword(t *testing.T) {
	input := `[server]
hostname = "mail.example.com"
`
	result := config.PatchRspamdChecker([]byte(input), "http://rspamd:11334", "")
	s := string(result)

	if !strings.Contains(s, `url = "http://rspamd:11334"`) {
		t.Errorf("expected url appended, got:\n%s", s)
	}
	if strings.Contains(s, "password") {
		t.Errorf("expected no password line when password is empty, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_InsertsMissingURL(t *testing.T) {
	input := `[[spamcheck.checkers]]
type = "rspamd"
timeout = "5s"
`
	result := config.PatchRspamdChecker([]byte(input), "http://localhost:11334", "")
	s := string(result)

	if !strings.Contains(s, `url = "http://localhost:11334"`) {
		t.Errorf("expected url inserted, got:\n%s", s)
	}
	if !strings.Contains(s, `timeout = "5s"`) {
		t.Errorf("expected timeout preserved, got:\n%s", s)
	}
}

func TestPatchRspamdChecker_InsertsMissingPassword(t *testing.T) {
	input := `[[spamcheck.checkers]]
type = "rspamd"
url = "http://localhost:11334"
`
	result := config.PatchRspamdChecker([]byte(input), "http://localhost:11334", "new-secret")
	s := string(result)

	if !strings.Contains(s, `password = "new-secret"`) {
		t.Errorf("expected password inserted, got:\n%s", s)
	}
}

// ── PatchSectionValue tests ──────────────────────────────────────────────────

const sectionValueConfig = `# Mail server configuration

[server]
hostname = "mail.example.com"
maildir = "/var/mail"

[smtpd]
log_level = "info"

[smtpd.limits]
max_message_size = 26214400
max_recipients = 100

[[smtpd.listeners]]
address = ":25"
mode = "smtp"

[spamcheck]
enabled = true
`

func TestPatchSectionValue_UpdateExisting(t *testing.T) {
	result := config.PatchSectionValue([]byte(sectionValueConfig), "server", "hostname", `"new.example.com"`)
	s := string(result)

	if !strings.Contains(s, `hostname = "new.example.com"`) {
		t.Errorf("expected updated hostname, got:\n%s", s)
	}
	if strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected old hostname replaced, got:\n%s", s)
	}
	if !strings.Contains(s, "# Mail server configuration") {
		t.Errorf("expected top comment preserved, got:\n%s", s)
	}
	if !strings.Contains(s, `maildir = "/var/mail"`) {
		t.Errorf("expected maildir preserved, got:\n%s", s)
	}
}

func TestPatchSectionValue_InsertMissing(t *testing.T) {
	result := config.PatchSectionValue([]byte(sectionValueConfig), "server", "domains_path", `"/var/mail/domains"`)
	s := string(result)

	if !strings.Contains(s, `domains_path = "/var/mail/domains"`) {
		t.Errorf("expected domains_path inserted, got:\n%s", s)
	}
	// Original keys preserved
	if !strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected hostname preserved, got:\n%s", s)
	}
}

func TestPatchSectionValue_PreservesOtherSections(t *testing.T) {
	result := config.PatchSectionValue([]byte(sectionValueConfig), "smtpd", "log_level", `"debug"`)
	s := string(result)

	if !strings.Contains(s, `log_level = "debug"`) {
		t.Errorf("expected updated log_level, got:\n%s", s)
	}
	// Other sections unchanged
	if !strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected [server] section preserved, got:\n%s", s)
	}
	if !strings.Contains(s, "enabled = true") {
		t.Errorf("expected [spamcheck] section preserved, got:\n%s", s)
	}
}

func TestPatchSectionValue_NoSection_Appends(t *testing.T) {
	result := config.PatchSectionValue([]byte(sectionValueConfig), "pop3d", "log_level", `"warn"`)
	s := string(result)

	if !strings.Contains(s, "[pop3d]") {
		t.Errorf("expected [pop3d] section appended, got:\n%s", s)
	}
	if !strings.Contains(s, `log_level = "warn"`) {
		t.Errorf("expected log_level appended, got:\n%s", s)
	}
	// Original content preserved
	if !strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected original content preserved, got:\n%s", s)
	}
}

func TestPatchSectionValue_RemoveKey(t *testing.T) {
	result := config.PatchSectionValue([]byte(sectionValueConfig), "server", "maildir", "")
	s := string(result)

	if strings.Contains(s, "maildir") {
		t.Errorf("expected maildir line removed, got:\n%s", s)
	}
	// Other keys preserved
	if !strings.Contains(s, `hostname = "mail.example.com"`) {
		t.Errorf("expected hostname preserved, got:\n%s", s)
	}
}

func TestPatchSectionValue_NestedSection(t *testing.T) {
	result := config.PatchSectionValue([]byte(sectionValueConfig), "smtpd.limits", "max_message_size", "52428800")
	s := string(result)

	if !strings.Contains(s, "max_message_size = 52428800") {
		t.Errorf("expected updated max_message_size, got:\n%s", s)
	}
	if strings.Contains(s, "max_message_size = 26214400") {
		t.Errorf("expected old value replaced, got:\n%s", s)
	}
	// Other limit preserved
	if !strings.Contains(s, "max_recipients = 100") {
		t.Errorf("expected max_recipients preserved, got:\n%s", s)
	}
}

func TestPatchSectionValue_LeavesArrayOfTablesAlone(t *testing.T) {
	// Editing [smtpd] must not touch [[smtpd.listeners]] which follows
	result := config.PatchSectionValue([]byte(sectionValueConfig), "smtpd", "log_level", `"error"`)
	s := string(result)

	if !strings.Contains(s, `log_level = "error"`) {
		t.Errorf("expected updated log_level, got:\n%s", s)
	}
	if !strings.Contains(s, `address = ":25"`) {
		t.Errorf("expected [[smtpd.listeners]] content preserved, got:\n%s", s)
	}
	if !strings.Contains(s, `mode = "smtp"`) {
		t.Errorf("expected listener mode preserved, got:\n%s", s)
	}
}

func TestQuoteString(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hello", `"hello"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
	}
	for _, tc := range cases {
		got := config.QuoteString(tc.input)
		if got != tc.want {
			t.Errorf("QuoteString(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ── PatchRspamdChecker tests (existing) ─────────────────────────────────────

func TestPatchRspamdChecker_QuotesSpecialChars(t *testing.T) {
	input := `[[spamcheck.checkers]]
type = "rspamd"
url = "http://localhost:11334"
`
	result := config.PatchRspamdChecker([]byte(input), `http://host/path?a=1`, `pass"word\n`)
	s := string(result)

	// Quotes and backslashes should be escaped
	if !strings.Contains(s, `url = "http://host/path?a=1"`) {
		t.Errorf("expected url with special chars, got:\n%s", s)
	}
	if !strings.Contains(s, `password = "pass\"word\\n"`) {
		t.Errorf("expected escaped password, got:\n%s", s)
	}
}
