package smtp

import (
	"io"
	"strings"
	"testing"
)

func stripToString(t *testing.T, msg, authserv string) string {
	t.Helper()
	out, err := io.ReadAll(stripAuthResults(strings.NewReader(msg), authserv))
	if err != nil {
		t.Fatalf("reading filtered message: %v", err)
	}
	return string(out)
}

func TestStripAuthResults(t *testing.T) {
	tests := []struct {
		name     string
		authserv string
		msg      string
		want     string
	}{
		{
			name:     "removes a forged header bearing our authserv-id",
			authserv: "mail.infodancer.net",
			msg: "From: attacker@evil.example\r\n" +
				"Authentication-Results: mail.infodancer.net; dkim=pass header.d=paypal.com\r\n" +
				"Subject: hello\r\n" +
				"\r\n" +
				"body\r\n",
			want: "From: attacker@evil.example\r\n" +
				"Subject: hello\r\n" +
				"\r\n" +
				"body\r\n",
		},
		{
			name:     "keeps another ADMD's header",
			authserv: "mail.infodancer.net",
			msg: "Authentication-Results: mx.google.com; spf=pass\r\n" +
				"\r\n" +
				"body\r\n",
			want: "Authentication-Results: mx.google.com; spf=pass\r\n" +
				"\r\n" +
				"body\r\n",
		},
		{
			name:     "matches the field name case-insensitively",
			authserv: "mail.infodancer.net",
			msg: "AUTHENTICATION-RESULTS: MAIL.INFODANCER.NET; dkim=pass\r\n" +
				"\r\n",
			want: "\r\n",
		},
		{
			name:     "removes folded continuation lines with the field",
			authserv: "mail.infodancer.net",
			msg: "Authentication-Results: mail.infodancer.net;\r\n" +
				"\tdkim=pass header.d=paypal.com;\r\n" +
				"\tspf=pass smtp.mailfrom=paypal.com\r\n" +
				"Subject: hello\r\n" +
				"\r\n" +
				"body\r\n",
			want: "Subject: hello\r\n\r\nbody\r\n",
		},
		{
			name:     "keeps folded continuations of a header it is not dropping",
			authserv: "mail.infodancer.net",
			msg: "Received: from a\r\n" +
				"\tby b\r\n" +
				"Authentication-Results: mail.infodancer.net; dkim=pass\r\n" +
				"\tcontinued\r\n" +
				"Subject: hello\r\n" +
				"\r\n",
			want: "Received: from a\r\n\tby b\r\nSubject: hello\r\n\r\n",
		},
		{
			name:     "removes every forged copy, not just the first",
			authserv: "mail.infodancer.net",
			msg: "Authentication-Results: mail.infodancer.net; dkim=pass\r\n" +
				"Subject: hello\r\n" +
				"Authentication-Results: mail.infodancer.net; spf=pass\r\n" +
				"\r\n" +
				"body\r\n",
			want: "Subject: hello\r\n\r\nbody\r\n",
		},
		{
			name:     "does not touch the body",
			authserv: "mail.infodancer.net",
			msg: "Subject: hello\r\n" +
				"\r\n" +
				"Authentication-Results: mail.infodancer.net; dkim=pass\r\n" +
				"more body\r\n",
			want: "Subject: hello\r\n" +
				"\r\n" +
				"Authentication-Results: mail.infodancer.net; dkim=pass\r\n" +
				"more body\r\n",
		},
		{
			name:     "tolerates bare LF line endings",
			authserv: "mail.infodancer.net",
			msg:      "Authentication-Results: mail.infodancer.net; dkim=pass\nSubject: hello\n\nbody\n",
			want:     "Subject: hello\n\nbody\n",
		},
		{
			name:     "a prefix of our authserv-id is a different ADMD",
			authserv: "mail.infodancer.net",
			msg:      "Authentication-Results: mail.infodancer.net.evil.example; dkim=pass\r\n\r\n",
			want:     "Authentication-Results: mail.infodancer.net.evil.example; dkim=pass\r\n\r\n",
		},
		{
			name:     "handles an authserv-id terminated by whitespace",
			authserv: "mail.infodancer.net",
			msg:      "Authentication-Results: mail.infodancer.net 1; dkim=pass\r\n\r\n",
			want:     "\r\n",
		},
		{
			name:     "a message with no header block at all is passed through",
			authserv: "mail.infodancer.net",
			msg:      "not really a message",
			want:     "not really a message",
		},
		{
			name:     "empty authserv-id disables filtering",
			authserv: "",
			msg:      "Authentication-Results: mail.infodancer.net; dkim=pass\r\n\r\n",
			want:     "Authentication-Results: mail.infodancer.net; dkim=pass\r\n\r\n",
		},
		{
			name:     "empty message",
			authserv: "mail.infodancer.net",
			msg:      "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripToString(t, tt.msg, tt.authserv); got != tt.want {
				t.Errorf("stripAuthResults()\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestStripAuthResults_OversizedLine covers a header line longer than the read
// chunk, where the drop decision made on the first chunk has to carry to the
// tail of the same line.
func TestStripAuthResults_OversizedLine(t *testing.T) {
	padding := strings.Repeat("x", 3*authResultsChunk)

	t.Run("dropped field longer than a chunk is dropped entirely", func(t *testing.T) {
		msg := "Authentication-Results: mail.infodancer.net; dkim=pass d=" + padding + "\r\n" +
			"Subject: hello\r\n\r\nbody\r\n"
		want := "Subject: hello\r\n\r\nbody\r\n"
		if got := stripToString(t, msg, "mail.infodancer.net"); got != want {
			t.Errorf("got %q (len %d), want %q", truncate(got), len(got), want)
		}
	})

	t.Run("kept field longer than a chunk survives intact", func(t *testing.T) {
		msg := "Subject: " + padding + "\r\n\r\nbody\r\n"
		if got := stripToString(t, msg, "mail.infodancer.net"); got != msg {
			t.Errorf("oversized non-matching header was altered: got len %d, want len %d", len(got), len(msg))
		}
	})
}

// TestStripAuthResults_LargeBody checks the pass-through path after the header
// block, where reads go straight to the underlying reader.
func TestStripAuthResults_LargeBody(t *testing.T) {
	body := strings.Repeat("the quick brown fox\r\n", 50000)
	msg := "Authentication-Results: mail.infodancer.net; dkim=pass\r\n" +
		"Subject: hello\r\n\r\n" + body
	want := "Subject: hello\r\n\r\n" + body

	if got := stripToString(t, msg, "mail.infodancer.net"); got != want {
		t.Errorf("large body mangled: got len %d, want len %d", len(got), len(want))
	}
}

func truncate(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func TestBuildAuthResultsHeader(t *testing.T) {
	if got := buildAuthResultsHeader(""); got != "" {
		t.Errorf("empty value should produce no header, got %q", got)
	}
	want := "Authentication-Results: mail.infodancer.net;\r\n\tspf=pass\r\n"
	if got := buildAuthResultsHeader("mail.infodancer.net;\r\n\tspf=pass"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAuthservIDOf(t *testing.T) {
	tests := []struct{ value, want string }{
		{"mail.example.net; spf=pass", "mail.example.net"},
		{"mail.example.net;spf=pass", "mail.example.net"},
		{"mail.example.net 1; spf=pass", "mail.example.net"},
		{"mail.example.net\r\n", "mail.example.net"},
		{"mail.example.net", "mail.example.net"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := authservIDOf(tt.value); got != tt.want {
			t.Errorf("authservIDOf(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
