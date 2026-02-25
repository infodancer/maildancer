package backend

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/mail"
	"strings"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"
	"github.com/infodancer/maildancer/msgstore"
)

// Search searches for messages matching the criteria.
func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	if s.messages == nil {
		return &imap.SearchData{}, nil
	}
	ctx := context.Background()

	var matchedSeqs imap.SeqSet
	var matchedUIDs imap.UIDSet

	for i, msg := range s.messages {
		seqNum := uint32(i + 1)
		uid := imap.UID(i + 1)

		if !s.matchesCriteria(ctx, msg, seqNum, uid, criteria) {
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

func (s *Session) matchesCriteria(ctx context.Context, info msgstore.MessageInfo, seqNum uint32, uid imap.UID, criteria *imap.SearchCriteria) bool {
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
		r, err := s.retrieveMessage(ctx, s.selectedMailbox, info.UID)
		if err != nil {
			return false
		}
		content, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return false
		}

		hdr, hdrErr := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(content)))

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

		contentStr := strings.ToLower(string(content))
		for _, term := range criteria.Body {
			if !strings.Contains(contentStr, strings.ToLower(term)) {
				return false
			}
		}
		for _, term := range criteria.Text {
			if !strings.Contains(contentStr, strings.ToLower(term)) {
				return false
			}
		}
	}

	for _, not := range criteria.Not {
		if s.matchesCriteria(ctx, info, seqNum, uid, &not) {
			return false
		}
	}

	for _, or := range criteria.Or {
		if !s.matchesCriteria(ctx, info, seqNum, uid, &or[0]) && !s.matchesCriteria(ctx, info, seqNum, uid, &or[1]) {
			return false
		}
	}

	return true
}
