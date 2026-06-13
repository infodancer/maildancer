package backend

import (
	"bufio"
	"bytes"
	"context"
	"net/mail"
	"strings"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"
	"github.com/infodancer/maildancer/msgstore"
)

// contentIndex holds the result of one batched content scan for a SEARCH:
// per-UID match data plus term->position maps so each criteria node can look
// up its predicates' results. Built once per Search (see prefetchContent) so
// message bodies are scanned a single time -- in mail-session when the store
// is the session-manager adapter -- instead of retrieved per criteria node.
type contentIndex struct {
	byUID   map[uint32]msgstore.ContentMatch
	bodyPos map[string]int // lowercased body term -> position in the scan
	textPos map[string]int // lowercased text term -> position in the scan
}

// Search searches for messages matching the criteria.
func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	if s.messages == nil {
		return &imap.SearchData{}, nil
	}
	ctx := context.Background()

	cc, err := s.prefetchContent(ctx, criteria)
	if err != nil {
		return nil, err
	}

	var matchedSeqs imap.SeqSet
	var matchedUIDs imap.UIDSet

	for i, msg := range s.messages {
		seqNum := uint32(i + 1)
		uid := imap.UID(msg.UID)

		if !s.matchesCriteria(cc, msg, seqNum, uid, criteria) {
			continue
		}

		if kind == imapserver.NumKindUID {
			matchedUIDs.AddNum(uid)
		} else {
			matchedSeqs.AddNum(seqNum)
		}
	}

	data := &imap.SearchData{}
	if kind == imapserver.NumKindUID {
		data.All = matchedUIDs
	} else {
		data.All = matchedSeqs
	}
	return data, nil
}

// prefetchContent runs a single content scan for every content predicate in
// the criteria tree. Returns nil (and no error) when the criteria has no
// content predicates -- the common flag/size/date searches never touch
// message bodies. When the store implements ContentSearcher (the
// session-manager adapter), the scan executes in mail-session and only
// headers + match booleans cross the proxy; otherwise it runs locally over
// the store.
func (s *Session) prefetchContent(ctx context.Context, criteria *imap.SearchCriteria) (*contentIndex, error) {
	var bodyTerms, textTerms []string
	bodySeen := map[string]bool{}
	textSeen := map[string]bool{}
	needHeaders := false
	hasContent := false
	collectContentTerms(criteria, &bodyTerms, &textTerms, bodySeen, textSeen, &needHeaders, &hasContent)
	if !hasContent {
		return nil, nil
	}

	uids := make([]uint32, len(s.messages))
	for i, m := range s.messages {
		uids[i] = m.UID
	}

	var matches []msgstore.ContentMatch
	var err error
	if cs, ok := s.store.(msgstore.ContentSearcher); ok {
		matches, err = cs.SearchContent(ctx, s.selectedMailbox, uids, bodyTerms, textTerms, needHeaders)
	} else {
		matches, err = msgstore.SearchContentStore(ctx, s.store, s.selectedMailbox, uids, bodyTerms, textTerms, needHeaders)
	}
	if err != nil {
		return nil, err
	}

	idx := &contentIndex{
		byUID:   make(map[uint32]msgstore.ContentMatch, len(matches)),
		bodyPos: make(map[string]int, len(bodyTerms)),
		textPos: make(map[string]int, len(textTerms)),
	}
	for i, t := range bodyTerms {
		idx.bodyPos[strings.ToLower(t)] = i
	}
	for i, t := range textTerms {
		idx.textPos[strings.ToLower(t)] = i
	}
	for _, m := range matches {
		idx.byUID[m.UID] = m
	}
	return idx, nil
}

// collectContentTerms walks the criteria tree (including Not and Or branches)
// accumulating the distinct body and text terms and whether any header or
// sent-date predicate is present (which requires the header block).
func collectContentTerms(c *imap.SearchCriteria, bodyTerms, textTerms *[]string, bodySeen, textSeen map[string]bool, needHeaders, hasContent *bool) {
	if len(c.Header) > 0 || !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
		*needHeaders = true
		*hasContent = true
	}
	for _, t := range c.Body {
		*hasContent = true
		if lt := strings.ToLower(t); !bodySeen[lt] {
			bodySeen[lt] = true
			*bodyTerms = append(*bodyTerms, t)
		}
	}
	for _, t := range c.Text {
		*hasContent = true
		if lt := strings.ToLower(t); !textSeen[lt] {
			textSeen[lt] = true
			*textTerms = append(*textTerms, t)
		}
	}
	for i := range c.Not {
		collectContentTerms(&c.Not[i], bodyTerms, textTerms, bodySeen, textSeen, needHeaders, hasContent)
	}
	for i := range c.Or {
		collectContentTerms(&c.Or[i][0], bodyTerms, textTerms, bodySeen, textSeen, needHeaders, hasContent)
		collectContentTerms(&c.Or[i][1], bodyTerms, textTerms, bodySeen, textSeen, needHeaders, hasContent)
	}
}

func (s *Session) matchesCriteria(cc *contentIndex, info msgstore.MessageInfo, seqNum uint32, uid imap.UID, criteria *imap.SearchCriteria) bool {
	for _, ss := range criteria.SeqNum {
		if !ss.Contains(seqNum) {
			return false
		}
	}

	for _, us := range criteria.UID {
		if !us.Contains(uid) {
			return false
		}
	}

	for _, reqFlag := range criteria.Flag {
		if !hasFlag(info.Flags, reqFlag) {
			return false
		}
	}

	for _, notFlag := range criteria.NotFlag {
		if hasFlag(info.Flags, notFlag) {
			return false
		}
	}

	if criteria.Larger > 0 && info.Size <= criteria.Larger {
		return false
	}
	if criteria.Smaller > 0 && info.Size >= criteria.Smaller {
		return false
	}

	if !criteria.Since.IsZero() || !criteria.Before.IsZero() {
		if info.InternalDate.IsZero() {
			return false
		}
		mtime := info.InternalDate.Truncate(24 * time.Hour)
		if !criteria.Since.IsZero() && mtime.Before(criteria.Since.Truncate(24*time.Hour)) {
			return false
		}
		if !criteria.Before.IsZero() && !mtime.Before(criteria.Before.Truncate(24*time.Hour)) {
			return false
		}
	}

	needContent := !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() ||
		len(criteria.Header) > 0 || len(criteria.Body) > 0 || len(criteria.Text) > 0

	if needContent {
		if cc == nil {
			return false
		}
		m, ok := cc.byUID[info.UID]
		if !ok {
			// Message could not be retrieved during the scan; exclude it,
			// matching the prior per-message retrieve-error behavior.
			return false
		}

		if len(criteria.Header) > 0 || !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() {
			hdr, hdrErr := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(m.Headers)))

			if !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() {
				var sentDate time.Time
				if hdrErr == nil {
					if dateStr := hdr.Get("Date"); dateStr != "" {
						if t, err := mail.ParseDate(dateStr); err == nil {
							sentDate = t
						}
					}
				}
				if sentDate.IsZero() {
					return false
				}
				sentDay := sentDate.Truncate(24 * time.Hour)
				if !criteria.SentSince.IsZero() && sentDay.Before(criteria.SentSince.Truncate(24*time.Hour)) {
					return false
				}
				if !criteria.SentBefore.IsZero() && !sentDay.Before(criteria.SentBefore.Truncate(24*time.Hour)) {
					return false
				}
			}

			for _, hf := range criteria.Header {
				if hdrErr != nil {
					return false
				}
				val := hdr.Get(hf.Key)
				if !strings.Contains(strings.ToLower(val), strings.ToLower(hf.Value)) {
					return false
				}
			}
		}

		for _, term := range criteria.Body {
			pos, ok := cc.bodyPos[strings.ToLower(term)]
			if !ok || pos >= len(m.BodyMatches) || !m.BodyMatches[pos] {
				return false
			}
		}
		for _, term := range criteria.Text {
			pos, ok := cc.textPos[strings.ToLower(term)]
			if !ok || pos >= len(m.TextMatches) || !m.TextMatches[pos] {
				return false
			}
		}
	}

	for _, not := range criteria.Not {
		if s.matchesCriteria(cc, info, seqNum, uid, &not) {
			return false
		}
	}

	for _, or := range criteria.Or {
		if !s.matchesCriteria(cc, info, seqNum, uid, &or[0]) && !s.matchesCriteria(cc, info, seqNum, uid, &or[1]) {
			return false
		}
	}

	return true
}
