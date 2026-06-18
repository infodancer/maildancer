package smtp

import (
	"strings"
	"testing"
	"time"
)

func mustParseTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, "2026-01-02T15:04:05-07:00")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func TestReceivedProto(t *testing.T) {
	cases := []struct {
		tls, auth bool
		want      string
	}{
		{false, false, "ESMTP"},
		{true, false, "ESMTPS"},
		{false, true, "ESMTPA"},
		{true, true, "ESMTPSA"},
	}
	for _, c := range cases {
		if got := receivedProto(c.tls, c.auth); got != c.want {
			t.Errorf("receivedProto(tls=%v, auth=%v) = %q, want %q", c.tls, c.auth, got, c.want)
		}
	}
}

func TestBuildReceivedHeader_Full(t *testing.T) {
	h := buildReceivedHeader(ReceivedInfo{
		Helo:           "client.example.org",
		ClientHostname: "mail.example.org",
		ClientIP:       "203.0.113.7",
		Hostname:       "mx.infodancer.net",
		Proto:          "ESMTPS",
		TLSComment:     "(version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384)",
		MsgID:          "deadbeef",
		ForRcpt:        "alice@infodancer.net",
	}, mustParseTime(t))

	for _, want := range []string{
		"Received: from client.example.org (mail.example.org [203.0.113.7])",
		"by mx.infodancer.net with ESMTPS id deadbeef",
		"(version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384)",
		"for <alice@infodancer.net>;",
		"Fri, 02 Jan 2026 15:04:05 -0700",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("header missing %q\n--- header ---\n%s", want, h)
		}
	}
	if !strings.HasPrefix(h, "Received: ") {
		t.Errorf("header must start with the field name; got %q", h)
	}
	if !strings.HasSuffix(h, "\r\n") {
		t.Errorf("header must end with CRLF; got %q", h)
	}
	// Folded continuation lines must begin with whitespace (RFC 5322).
	for _, line := range strings.Split(strings.TrimRight(h, "\r\n"), "\r\n")[1:] {
		if line == "" || (line[0] != ' ' && line[0] != '\t') {
			t.Errorf("continuation line not folded with whitespace: %q", line)
		}
	}
}

func TestBuildReceivedHeader_OmitsUnknownValues(t *testing.T) {
	// No reverse DNS, no TLS, multiple recipients (no "for").
	h := buildReceivedHeader(ReceivedInfo{
		Helo:     "bot",
		ClientIP: "198.51.100.4",
		Hostname: "mx.infodancer.net",
		Proto:    "ESMTP",
		MsgID:    "abc123",
	}, mustParseTime(t))

	if !strings.Contains(h, "from bot (unknown [198.51.100.4])") {
		t.Errorf("missing PTR-unknown rendering; got %q", h)
	}
	if strings.Contains(h, "version=") {
		t.Errorf("plaintext session must not emit a TLS comment; got %q", h)
	}
	if strings.Contains(h, "for <") {
		t.Errorf("multi/zero-recipient header must omit the for clause; got %q", h)
	}
}

func TestBuildForwardReceivedHeader(t *testing.T) {
	h := buildForwardReceivedHeader("mx.infodancer.net", "matthew@oldschoolgamers.org", "id99", mustParseTime(t))
	for _, want := range []string{
		"Received: by mx.infodancer.net (forwarding for <matthew@oldschoolgamers.org>)",
		"id id99;",
		"X-Original-To: matthew@oldschoolgamers.org",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("forward header missing %q\n--- header ---\n%s", want, h)
		}
	}
}
