package smtp

import (
	"crypto/tls"
	"io"
	"strings"
	"time"
)

// withHeaders returns a reader that yields the given header bytes followed by
// the message body, so a trace header is prepended without rewriting the
// buffer.
func withHeaders(headers string, body io.Reader) io.Reader {
	return io.MultiReader(strings.NewReader(headers), body)
}

// receivedDateFormat is the RFC 5322 date-time used in trace headers.
const receivedDateFormat = "Mon, 02 Jan 2006 15:04:05 -0700"

// receivedProto returns the RFC 3848 "with" protocol keyword for the session
// state: ESMTP, plus S when the connection used TLS and A when the client
// authenticated.
func receivedProto(isTLS, authenticated bool) string {
	switch {
	case isTLS && authenticated:
		return "ESMTPSA"
	case isTLS:
		return "ESMTPS"
	case authenticated:
		return "ESMTPA"
	default:
		return "ESMTP"
	}
}

// tlsComment renders the RFC 8601-style TLS detail comment for a Received
// header, e.g. "(version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384)". It returns the
// empty string when the connection is not TLS.
func tlsComment(st tls.ConnectionState, ok bool) string {
	if !ok {
		return ""
	}
	return "(version=" + tls.VersionName(st.Version) + " cipher=" + tls.CipherSuiteName(st.CipherSuite) + ")"
}

// ReceivedInfo carries every RFC 5321 section 4.4 trace value available for a
// message. Fields we do not (yet) know are left empty and omitted from the
// rendered header rather than faked.
type ReceivedInfo struct {
	Helo           string // EHLO/HELO name the client announced
	ClientHostname string // validated reverse DNS (PTR) of the client, "" if none
	ClientIP       string // client IP literal
	Hostname       string // our receiving host
	Proto          string // RFC 3848 "with" keyword (ESMTP/ESMTPS/ESMTPSA/...)
	TLSComment     string // tlsComment(), "" when not TLS
	MsgID          string // our internal correlation id (the "id" clause)
	ForRcpt        string // single recipient for the "for" clause, "" to omit
}

// buildReceivedHeader builds the RFC 5321 section 4.4 ingress trace header as a
// single folded header field ending in CRLF. It encodes every value we have:
//
//	Received: from HELO (rdns [ip])
//		by HOST with ESMTPS id MSGID
//		(version=... cipher=...)
//		for <rcpt>;
//		Mon, 02 Jan 2006 15:04:05 -0700
//
// The reverse-DNS, TLS comment, and "for" clause are emitted only when known.
// Per RFC 5321 the "for" clause is limited to one recipient, so callers pass it
// only for a single-recipient message; with several it is omitted rather than
// disclose the others.
func buildReceivedHeader(info ReceivedInfo, now time.Time) string {
	helo := info.Helo
	if helo == "" {
		helo = "unknown"
	}
	rdns := info.ClientHostname
	if rdns == "" {
		rdns = "unknown"
	}

	lines := []string{
		"Received: from " + helo + " (" + rdns + " [" + info.ClientIP + "])",
		"\tby " + info.Hostname + " with " + info.Proto + " id " + info.MsgID,
	}
	if info.TLSComment != "" {
		lines = append(lines, "\t"+info.TLSComment)
	}
	if info.ForRcpt != "" {
		lines = append(lines, "\tfor <"+info.ForRcpt+">")
	}
	return strings.Join(lines, "\r\n") + ";\r\n\t" + now.Format(receivedDateFormat) + "\r\n"
}

// buildForwardReceivedHeader builds the trace headers for the forwarding hop
// when an alias is re-sent to its target (RFC 5321 section 3.9.2: an alias adds
// trace fields). It records the redirect as its own Received line and adds the
// de-facto X-Original-To marker naming the alias that was forwarded, so the
// final recipient can see the message arrived via a forward. The result ends in
// CRLF and is prepended above the ingress Received header.
func buildForwardReceivedHeader(hostname, original, msgid string, now time.Time) string {
	var b strings.Builder
	b.WriteString("Received: by ")
	b.WriteString(hostname)
	b.WriteString(" (forwarding for <")
	b.WriteString(original)
	b.WriteString(">)\r\n\tid ")
	b.WriteString(msgid)
	b.WriteString(";\r\n\t")
	b.WriteString(now.Format(receivedDateFormat))
	b.WriteString("\r\nX-Original-To: ")
	b.WriteString(original)
	b.WriteString("\r\n")
	return b.String()
}
