package smtp

import (
	"strings"
	"testing"
)

// TestBuildSpamHeaders_Deterministic guards against map iteration order leaking
// into the wire format. CheckResult.Headers is a map, so an unordered render
// would reshuffle the header block on every delivery -- breaking byte-for-byte
// tests, DKIM over any of these fields, and any diffing of stored messages.
func TestBuildSpamHeaders_Deterministic(t *testing.T) {
	in := map[string]string{
		"X-Spam-Status":  "Yes, score=12.80 required=15.00",
		"X-Spam-Score":   "12.80",
		"X-Spam-Value":   "9",
		"X-Spam-Flag":    "YES",
		"X-Spam-Checker": "rspamd",
		"X-Rspamd-Extra": "something",
	}

	first := buildSpamHeaders(in)
	for range 50 {
		if got := buildSpamHeaders(in); got != first {
			t.Fatalf("render is not deterministic:\n%q\nvs\n%q", first, got)
		}
	}

	// The well-known fields lead, in a fixed order, so the block reads the same
	// way everywhere; anything else follows sorted.
	want := "X-Spam-Flag: YES\r\n" +
		"X-Spam-Value: 9\r\n" +
		"X-Spam-Score: 12.80\r\n" +
		"X-Spam-Status: Yes, score=12.80 required=15.00\r\n" +
		"X-Spam-Checker: rspamd\r\n" +
		"X-Rspamd-Extra: something\r\n"
	if first != want {
		t.Errorf("buildSpamHeaders() =\n%q\nwant\n%q", first, want)
	}
}

// TestBuildSpamHeaders_Empty: nothing to say means no bytes, so callers can
// concatenate the result unconditionally.
func TestBuildSpamHeaders_Empty(t *testing.T) {
	if got := buildSpamHeaders(nil); got != "" {
		t.Errorf("buildSpamHeaders(nil) = %q, want empty", got)
	}
	if got := buildSpamHeaders(map[string]string{}); got != "" {
		t.Errorf("buildSpamHeaders(empty) = %q, want empty", got)
	}
}

// TestBuildSpamHeaders_RejectsInjection is the security case. Header values
// reach us from rspamd (including its milter add_headers, which is operator- or
// rule-controlled), so a value containing CRLF must not be able to terminate the
// field and inject a header of the attacker's choosing -- least of all a second
// X-Spam-Flag that a Sieve rule might read instead of ours.
func TestBuildSpamHeaders_RejectsInjection(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
	}{
		{"CRLF in value", map[string]string{
			"X-Spam-Flag": "NO\r\nX-Spam-Value: 1",
		}},
		{"bare LF in value", map[string]string{
			"X-Spam-Flag": "NO\nX-Spam-Value: 1",
		}},
		{"bare CR in value", map[string]string{
			"X-Spam-Flag": "NO\rX-Spam-Value: 1",
		}},
		{"CRLF in name", map[string]string{
			"X-Spam-Flag\r\nX-Spam-Value": "1",
		}},
		{"colon in name", map[string]string{
			"X-Spam-Flag: NO\r\nX-Evil": "1",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSpamHeaders(tt.in)

			// Exactly one field: one CRLF, at the very end.
			if n := strings.Count(got, "\r\n"); n > 1 {
				t.Errorf("value injected an extra field (%d CRLF):\n%q", n, got)
			}
			if strings.Contains(got, "\n") && !strings.HasSuffix(got, "\r\n") {
				t.Errorf("stray newline in rendered header:\n%q", got)
			}
			if strings.Contains(strings.TrimSuffix(got, "\r\n"), "\r") {
				t.Errorf("stray CR in rendered header:\n%q", got)
			}
			// The property that matters is that injected text stays inside a
			// field value and never becomes a field of its own. Matching on the
			// literal text would be the wrong assertion: "X-Spam-Value: 1"
			// sitting in the value of X-Spam-Flag is inert, because a parser
			// takes the field name up to the first colon and the rest is value.
			// Dropping the entry outright is a valid outcome, and the one a bad
			// field name gets -- an unusable name is not repaired, because
			// stripping bytes out of it could turn it into a different
			// well-known field.
			if got == "" {
				return
			}

			body := strings.TrimSuffix(got, "\r\n")
			if strings.ContainsAny(body, "\r\n") {
				t.Errorf("injected text escaped into a second field:\n%q", got)
			}
			if name, _, found := strings.Cut(body, ":"); !found || !strings.EqualFold(name, "X-Spam-Flag") {
				t.Errorf("rendered field is not the one we set (name=%q):\n%q", name, got)
			}
		})
	}
}

// TestBuildSpamHeaders_DropsUnusableNames: a name that is not a valid field name
// is dropped rather than sanitized into a different header, so a malformed key
// can never be silently reinterpreted as a well-known one.
func TestBuildSpamHeaders_DropsUnusableNames(t *testing.T) {
	got := buildSpamHeaders(map[string]string{
		"":            "value",
		" ":           "value",
		"X-Spam-Flag": "YES",
	})
	if got != "X-Spam-Flag: YES\r\n" {
		t.Errorf("buildSpamHeaders() = %q, want only the valid field", got)
	}
}
