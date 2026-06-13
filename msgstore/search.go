package msgstore

import (
	"bytes"
	"context"
	"io"
)

// ContentMatch is the result of evaluating content predicates against one
// message. Headers is the RFC 5322 header block (present only when requested);
// BodyMatches and TextMatches are aligned with the bodyTerms and textTerms
// passed to SearchContent.
type ContentMatch struct {
	UID         uint32
	Headers     []byte
	BodyMatches []bool
	TextMatches []bool
}

// ContentSearcher is implemented by stores (or store adapters) that can
// evaluate content predicates without returning whole message bodies to the
// caller -- notably the imapd session-manager adapter, which evaluates them in
// mail-session so plaintext never crosses the proxy. Stores that do not
// implement it fall back to SearchContentStore over the MessageStore interface.
type ContentSearcher interface {
	SearchContent(ctx context.Context, folder string, uids []uint32, bodyTerms, textTerms []string, needHeaders bool) ([]ContentMatch, error)
}

// SearchContentStore evaluates content predicates for a set of messages by
// retrieving each one from the store and testing substrings. It is the shared
// implementation behind both the local path (maildir, tests) and the
// mail-session gRPC handler; the transport differs, the semantics do not.
//
// bodyTerms are tested against the message body only; textTerms against the
// whole message (headers + body), per RFC 3501 BODY vs TEXT. Matching is
// case-insensitive octet containment. When needHeaders is set, each result
// carries the message's header block so the caller can evaluate header and
// date predicates without the body.
//
// folder may be "INBOX". An empty uids slice means every message in the folder.
// A message that cannot be retrieved is skipped (no result entry), mirroring
// the prior per-message search behavior where a retrieve error excluded the
// message.
func SearchContentStore(ctx context.Context, store MessageStore, folder string, uids []uint32, bodyTerms, textTerms []string, needHeaders bool) ([]ContentMatch, error) {
	if len(uids) == 0 {
		infos, err := listFolder(ctx, store, folder)
		if err != nil {
			return nil, err
		}
		uids = make([]uint32, len(infos))
		for i, info := range infos {
			uids[i] = info.UID
		}
	}

	results := make([]ContentMatch, 0, len(uids))
	for _, uid := range uids {
		rc, err := retrieve(ctx, store, folder, uid)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			continue
		}
		results = append(results, MatchMessageContent(data, uid, bodyTerms, textTerms, needHeaders))
	}
	return results, nil
}

// MatchMessageContent evaluates content predicates against one raw message.
// bodyTerms are tested against the body only, textTerms against the whole
// message (headers + body); matching is case-insensitive octet containment.
// Headers are returned only when needHeaders is set. Shared by
// SearchContentStore (imapd local/mock path) and the mail-session gRPC
// SearchContent handler so both compute identical results.
func MatchMessageContent(data []byte, uid uint32, bodyTerms, textTerms []string, needHeaders bool) ContentMatch {
	header, body := splitMessage(data)
	lowerWhole := bytes.ToLower(data)
	lowerBodyBytes := bytes.ToLower(body)

	m := ContentMatch{UID: uid}
	if needHeaders {
		m.Headers = header
	}
	if len(bodyTerms) > 0 {
		m.BodyMatches = make([]bool, len(bodyTerms))
		for i, term := range bodyTerms {
			m.BodyMatches[i] = bytes.Contains(lowerBodyBytes, bytes.ToLower([]byte(term)))
		}
	}
	if len(textTerms) > 0 {
		m.TextMatches = make([]bool, len(textTerms))
		for i, term := range textTerms {
			m.TextMatches[i] = bytes.Contains(lowerWhole, bytes.ToLower([]byte(term)))
		}
	}
	return m
}

// listFolder lists a folder via FolderStore when folder is not INBOX,
// otherwise via the base MessageStore.
func listFolder(ctx context.Context, store MessageStore, folder string) ([]MessageInfo, error) {
	if folder == "" || folder == "INBOX" || folder == "inbox" {
		return store.List(ctx, "")
	}
	if fs, ok := store.(FolderStore); ok {
		return fs.ListInFolder(ctx, "", folder)
	}
	return store.List(ctx, "")
}

// retrieve fetches a message from a folder via FolderStore when folder is not
// INBOX, otherwise via the base MessageStore.
func retrieve(ctx context.Context, store MessageStore, folder string, uid uint32) (io.ReadCloser, error) {
	if folder == "" || folder == "INBOX" || folder == "inbox" {
		return store.Retrieve(ctx, "", uid)
	}
	if fs, ok := store.(FolderStore); ok {
		return fs.RetrieveFromFolder(ctx, "", folder, uid)
	}
	return store.Retrieve(ctx, "", uid)
}

// splitMessage splits raw RFC 5322 bytes into the header block (including the
// terminating blank line) and the body. Handles both CRLF and LF separators.
// A message with no blank-line separator is treated as all headers, empty body.
func splitMessage(data []byte) (header, body []byte) {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return data[:i+4], data[i+4:]
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return data[:i+2], data[i+2:]
	}
	return data, nil
}
