package smtp

import (
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

func TestBuildSpamHeaders_Order(t *testing.T) {
	result := &spamcheck.CheckResult{
		Headers: map[string]string{
			"X-Spam-Checker": "rspamd",
			"X-Spam-Score":   "8.20",
			"X-Spam-Flag":    "YES",
			"X-Spam-Status":  "Yes, score=8.20 required=6.00",
			"X-Custom-Foo":   "bar",
		},
	}

	got := buildSpamHeaders(result, true)
	want := "X-Spam-Flag: YES\r\n" +
		"X-Spam-Status: Yes, score=8.20 required=6.00\r\n" +
		"X-Spam-Score: 8.20\r\n" +
		"X-Spam-Checker: rspamd\r\n" +
		"X-Custom-Foo: bar\r\n"
	if got != want {
		t.Errorf("buildSpamHeaders() =\n%q\nwant\n%q", got, want)
	}
}

func TestBuildSpamHeaders_Disabled(t *testing.T) {
	result := &spamcheck.CheckResult{Headers: map[string]string{"X-Spam-Flag": "YES"}}
	if got := buildSpamHeaders(result, false); got != "" {
		t.Errorf("buildSpamHeaders(add=false) = %q, want empty", got)
	}
}

func TestBuildSpamHeaders_NilAndEmpty(t *testing.T) {
	if got := buildSpamHeaders(nil, true); got != "" {
		t.Errorf("buildSpamHeaders(nil) = %q, want empty", got)
	}
	if got := buildSpamHeaders(&spamcheck.CheckResult{}, true); got != "" {
		t.Errorf("buildSpamHeaders(no headers) = %q, want empty", got)
	}
}

func TestBuildSpamHeaders_StripsInjection(t *testing.T) {
	result := &spamcheck.CheckResult{
		Headers: map[string]string{
			"X-Spam-Flag": "YES\r\nBcc: attacker@evil.example",
		},
	}
	got := buildSpamHeaders(result, true)
	if strings.Contains(got, "Bcc:") && strings.Contains(got, "\r\nBcc:") {
		t.Errorf("injected header line survived: %q", got)
	}
	if want := "X-Spam-Flag: YESBcc: attacker@evil.example\r\n"; got != want {
		t.Errorf("buildSpamHeaders() = %q, want %q", got, want)
	}
}
