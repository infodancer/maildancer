package rspamd

import (
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// symbols is a shorthand for building an rspamd symbol map in tests.
func symbols(pairs ...interface{}) map[string]SymbolResult {
	m := make(map[string]SymbolResult)
	for i := 0; i < len(pairs); i += 2 {
		name := pairs[i].(string)
		var opts []string
		if pairs[i+1] != nil {
			opts = pairs[i+1].([]string)
		}
		m[name] = SymbolResult{Name: name, Options: opts}
	}
	return m
}

func TestBuildAuthResults(t *testing.T) {
	defaultOpts := spamcheck.CheckOptions{
		Hostname: "mail.infodancer.net",
		From:     "pm_bounces@pm-bounces.matthewjayhunter.com",
		Helo:     "mail.postmarkapp.com",
	}

	tests := []struct {
		name   string
		result RspamdResult
		opts   spamcheck.CheckOptions
		want   string
	}{
		{
			name: "all three methods pass",
			result: RspamdResult{Symbols: symbols(
				"R_SPF_ALLOW", []string{"+ip4:1.2.3.4"},
				"R_DKIM_ALLOW", []string{"matthewjayhunter.com:s=20260519"},
				"DMARC_POLICY_ALLOW", []string{"matthewjayhunter.com", "none"},
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n" +
				"\tspf=pass smtp.mailfrom=pm-bounces.matthewjayhunter.com;\r\n" +
				"\tdkim=pass header.d=matthewjayhunter.com header.s=20260519;\r\n" +
				"\tdmarc=pass header.from=matthewjayhunter.com",
		},
		{
			name: "failures are reported as failures, not omitted",
			result: RspamdResult{Symbols: symbols(
				"R_SPF_FAIL", []string{"-all"},
				"R_DKIM_REJECT", []string{"evil.example:s=k1"},
				"DMARC_POLICY_REJECT", []string{"paypal.com", "reject"},
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n" +
				"\tspf=fail smtp.mailfrom=pm-bounces.matthewjayhunter.com;\r\n" +
				"\tdkim=fail header.d=evil.example header.s=k1;\r\n" +
				"\tdmarc=fail header.from=paypal.com",
		},
		{
			name: "quarantine policy is a dmarc failure",
			result: RspamdResult{Symbols: symbols(
				"DMARC_POLICY_QUARANTINE", []string{"example.com", "quarantine"},
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n\tdmarc=fail header.from=example.com",
		},
		{
			name: "only the methods rspamd reported are emitted",
			result: RspamdResult{Symbols: symbols(
				"R_SPF_NEUTRAL", nil,
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n\tspf=neutral smtp.mailfrom=pm-bounces.matthewjayhunter.com",
		},
		{
			name: "dkim without a selector reports only the domain",
			result: RspamdResult{Symbols: symbols(
				"R_DKIM_ALLOW", []string{"example.com"},
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n\tdkim=pass header.d=example.com",
		},
		{
			name: "dkim with no options omits the property rather than inventing one",
			result: RspamdResult{Symbols: symbols(
				"R_DKIM_ALLOW", nil,
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n\tdkim=pass",
		},
		{
			name: "null return-path falls back to the HELO identity",
			result: RspamdResult{Symbols: symbols(
				"R_SPF_ALLOW", nil,
			)},
			opts: spamcheck.CheckOptions{Hostname: "mail.infodancer.net", From: "", Helo: "mail.postmarkapp.com"},
			want: "mail.infodancer.net;\r\n\tspf=pass smtp.helo=mail.postmarkapp.com",
		},
		{
			name:   "no authentication symbols yields no header",
			result: RspamdResult{Symbols: symbols("BAYES_HAM", nil, "MIME_GOOD", nil)},
			opts:   defaultOpts,
			want:   "",
		},
		{
			name:   "no symbols at all yields no header",
			result: RspamdResult{},
			opts:   defaultOpts,
			want:   "",
		},
		{
			name: "no authserv-id yields no header",
			result: RspamdResult{Symbols: symbols(
				"R_SPF_ALLOW", nil,
			)},
			opts: spamcheck.CheckOptions{Hostname: ""},
			want: "",
		},
		{
			name: "explicit none verdicts are reported",
			result: RspamdResult{Symbols: symbols(
				"R_SPF_NA", nil,
				"R_DKIM_NA", nil,
				"DMARC_NA", nil,
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n" +
				"\tspf=none smtp.mailfrom=pm-bounces.matthewjayhunter.com;\r\n" +
				"\tdkim=none;\r\n" +
				"\tdmarc=none",
		},
		{
			name: "arc verdicts are reported",
			result: RspamdResult{Symbols: symbols(
				"ARC_ALLOW", []string{"example.com"},
			)},
			opts: defaultOpts,
			want: "mail.infodancer.net;\r\n\tarc=pass",
		},
		{
			name: "rspamd's own header is preferred when it supplies one",
			result: RspamdResult{
				Symbols: symbols("R_SPF_ALLOW", nil),
				Milter: &MilterResult{AddHeaders: map[string]HeaderValue{
					"Authentication-Results": {Value: "mail.infodancer.net; dkim=pass header.d=example.com; spf=pass"},
				}},
			},
			opts: defaultOpts,
			want: "mail.infodancer.net; dkim=pass header.d=example.com; spf=pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAuthResults(&tt.result, tt.opts)
			if got != tt.want {
				t.Errorf("buildAuthResults()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestBuildAuthResults_NoHeaderInjection is the security case: every property
// value is taken from the message or the SMTP envelope, so a domain containing
// CRLF must not be able to append a second header field.
func TestBuildAuthResults_NoHeaderInjection(t *testing.T) {
	injections := []string{
		"evil.example\r\nAuthentication-Results: mail.infodancer.net; dkim=pass",
		"evil.example\nX-Injected: yes",
		"evil.example; dkim=pass",
		"evil.example\r\n\tfolded continuation",
	}

	for _, bad := range injections {
		t.Run(bad, func(t *testing.T) {
			got := buildAuthResults(&RspamdResult{
				Symbols: symbols("DMARC_POLICY_ALLOW", []string{bad}),
			}, spamcheck.CheckOptions{Hostname: "mail.infodancer.net"})

			// The only line breaks allowed are the folds we generate, which are
			// always CRLF followed by a tab. Remove those; nothing may remain.
			if unfolded := strings.ReplaceAll(got, "\r\n\t", ""); strings.ContainsAny(unfolded, "\r\n") {
				t.Fatalf("unfolded line break injected into %q", got)
			}

			// The injected text may survive as inert characters inside the
			// property value, but it must not become a separate clause: the only
			// semicolons are the ones we emit as method separators, so the
			// attacker's "dkim=pass" cannot be parsed as its own verdict.
			wantSemicolons := strings.Count(got, ";\r\n\t")
			if got := strings.Count(got, ";"); got != wantSemicolons {
				t.Errorf("found %d semicolons, want %d -- injected clause separator survived", got, wantSemicolons)
			}
			if strings.Contains(strings.ToLower(got), "; dkim=pass") {
				t.Errorf("injected dkim clause survived: %q", got)
			}
		})
	}
}

// TestBuildAuthResults_SanitizesRspamdSuppliedHeader covers the same injection
// risk on the path where rspamd hands us a whole field value.
func TestBuildAuthResults_SanitizesRspamdSuppliedHeader(t *testing.T) {
	got := buildAuthResults(&RspamdResult{
		Milter: &MilterResult{AddHeaders: map[string]HeaderValue{
			"Authentication-Results": {Value: "mail.infodancer.net; spf=pass\r\nX-Injected: yes"},
		}},
	}, spamcheck.CheckOptions{Hostname: "mail.infodancer.net"})

	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("line break survived sanitization: %q", got)
	}
	if got != "mail.infodancer.net; spf=passX-Injected: yes" {
		t.Logf("sanitized to %q", got)
	}
}

func TestDomainOf(t *testing.T) {
	tests := []struct{ addr, want string }{
		{"user@example.com", "example.com"},
		{"user@sub.example.com", "sub.example.com"},
		{"", ""},
		{"nodomain", ""},
		{"trailing@", ""},
		{"a@b@c.example", "c.example"},
	}
	for _, tt := range tests {
		if got := domainOf(tt.addr); got != tt.want {
			t.Errorf("domainOf(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}
