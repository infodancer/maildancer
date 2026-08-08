package smtp

import (
	"bufio"
	"io"
	"strings"
)

// Authentication-Results handling on ingress.
//
// Stamping a verdict is only worth anything if the verdict cannot be forged.
// RFC 8601 section 7.1: a message arriving from outside the ADMD may already
// carry an Authentication-Results header claiming our authserv-id, and a
// consumer that does not take strictly the topmost one -- a sieve rule, an MUA
// indicator, a downstream filter -- would read the attacker's "dkim=pass"
// instead of ours. So every such header is removed before ours is added.
//
// Headers bearing some *other* authserv-id are left alone: they are another
// ADMD's findings and are not ours to discard.

// authResultsFieldName is the header field we stamp and strip, lowercased with
// its colon so a line prefix can be compared directly.
const authResultsFieldName = "authentication-results:"

// authResultsChunk bounds how much of a single header line is examined at once.
// RFC 5322 limits a line to 998 octets; anything longer is passed through in
// chunks rather than buffered whole, so a hostile message cannot make us
// allocate without limit.
const authResultsChunk = 8 << 10

// messageBody returns the accepted message with the given trace headers
// prepended and the inbound copies of any header we stamp ourselves removed.
// Every delivery path builds its body through here so the strip cannot be
// forgotten on one of them.
func (s *Session) messageBody(headers string, tmp tempBuffer) io.Reader {
	return withHeaders(headers, s.stripStampedHeaders(tmp.reader()))
}

// stripStampedHeaders removes inbound header fields that would be confused with
// the ones this MTA stamps:
//
//   - Authentication-Results bearing our own authserv-id, always. RFC 8601
//     section 7.1; another ADMD's is left alone, being theirs to assert.
//   - X-Spam-*, but only when spam-header stamping is enabled. There is no
//     authserv-id equivalent on these fields, so ours cannot be told from an
//     upstream's -- the only way to guarantee a Sieve rule reads our verdict is
//     to be the sole source of them. When stamping is off there is nothing of
//     ours to confuse them with, and an upstream filter's headers are real data
//     a user may be matching on deliberately, so they are left in place.
func (s *Session) stripStampedHeaders(msg io.Reader) io.Reader {
	authserv := strings.ToLower(s.backend.hostname)
	stripSpam := s.backend.spamConfig.AddHeaders

	if authserv == "" && !stripSpam {
		return msg
	}

	return &headerFilter{
		br:        bufio.NewReaderSize(msg, authResultsChunk),
		inHeaders: true,
		lineStart: true,
		drop: func(line []byte) bool {
			if stripSpam && isSpamHeaderLine(line) {
				return true
			}
			return authserv != "" && isOwnAuthResults(line, authserv)
		},
	}
}

// buildAuthResultsHeader renders a complete Authentication-Results header field,
// ending in CRLF, from a folded field value. It returns "" for an empty value so
// callers can concatenate the result unconditionally.
func buildAuthResultsHeader(value string) string {
	if value == "" {
		return ""
	}
	return authResultsHeaderName + ": " + value + "\r\n"
}

// authResultsHeaderName is the canonical field name we emit.
const authResultsHeaderName = "Authentication-Results"

// stripAuthResults returns a reader over msg with every Authentication-Results
// header field whose authserv-id equals authservID removed. It is the
// Authentication-Results-only case of stripStampedHeaders, kept separate so the
// RFC 8601 behaviour can be exercised without building a Session.
func stripAuthResults(msg io.Reader, authservID string) io.Reader {
	if authservID == "" {
		return msg
	}
	authserv := strings.ToLower(authservID)
	return &headerFilter{
		br:        bufio.NewReaderSize(msg, authResultsChunk),
		inHeaders: true,
		lineStart: true,
		drop:      func(line []byte) bool { return isOwnAuthResults(line, authserv) },
	}
}

// headerFilter removes whole header fields from a message as it is read,
// including their folded continuation lines. Only the header block is examined;
// once the blank line separating headers from body is seen the remainder is
// copied verbatim.
//
// Which fields go is the caller's decision, supplied as drop -- it is called
// once per field, with the line that starts it.
//
// Filtering is lazy and allocation-bounded: it reads one line-sized chunk at a
// time and holds no goroutine, so an abandoned reader leaks nothing.
type headerFilter struct {
	br   *bufio.Reader
	drop func(line []byte) bool

	buf     []byte // backing array for pending, reused between chunks
	pending []byte // filtered bytes not yet returned to the caller

	inHeaders bool
	lineStart bool // next chunk begins a new line
	dropping  bool // discarding the header field currently being read
	err       error
}

func (f *headerFilter) Read(p []byte) (int, error) {
	for len(f.pending) == 0 {
		if !f.inHeaders {
			// Past the header block: hand the rest through untouched. Any
			// buffered remainder is drained by the bufio.Reader first.
			if f.err != nil {
				return 0, f.err
			}
			return f.br.Read(p)
		}
		if f.err != nil {
			return 0, f.err
		}
		f.fill()
	}
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

// fill reads the next chunk and either buffers it for emission or discards it.
func (f *headerFilter) fill() {
	chunk, err := f.br.ReadSlice('\n')
	// ErrBufferFull means the line is longer than the chunk size; the rest
	// arrives on later calls and must inherit the current drop decision.
	partial := err == bufio.ErrBufferFull
	if err != nil && !partial {
		f.err = err
	}
	if len(chunk) == 0 {
		return
	}

	atLineStart := f.lineStart
	f.lineStart = !partial

	switch {
	case atLineStart && isBlankLine(chunk):
		// End of the header block; everything after this is body.
		f.inHeaders = false
		f.dropping = false
	case atLineStart && !isFoldedContinuation(chunk):
		f.dropping = f.drop(chunk)
	}
	// A folded continuation, or the tail of an over-long line, keeps whatever
	// decision was made for the field it belongs to.

	if f.dropping {
		return
	}
	f.buf = append(f.buf[:0], chunk...)
	f.pending = f.buf
}

// isOwnAuthResults reports whether a header line starts an Authentication-Results
// field whose authserv-id equals authserv, which must already be lowercased.
func isOwnAuthResults(line []byte, authserv string) bool {
	if len(line) < len(authResultsFieldName) {
		return false
	}
	if !strings.EqualFold(string(line[:len(authResultsFieldName)]), authResultsFieldName) {
		return false
	}
	value := strings.TrimLeft(string(line[len(authResultsFieldName):]), " \t")
	return strings.EqualFold(authservIDOf(value), authserv)
}

// authservIDOf returns the leading authserv-id token of an
// Authentication-Results field value. RFC 8601 allows an optional version number
// after the identifier and requires a semicolon before the first method, so the
// token ends at the first space, tab, semicolon, or line ending.
func authservIDOf(value string) string {
	end := strings.IndexAny(value, " \t;\r\n")
	if end < 0 {
		return strings.TrimSpace(value)
	}
	return value[:end]
}

func isBlankLine(line []byte) bool {
	return string(line) == "\r\n" || string(line) == "\n"
}

func isFoldedContinuation(line []byte) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}
