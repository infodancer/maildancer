// Package backend implements the IMAP session backed by go-maildir.
package backend

import (
	"bufio"
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"log/slog"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-maildir"
	"github.com/emersion/go-message/textproto"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/imapd/config"
	"github.com/infodancer/maildancer/internal/imapd/logging"
	"github.com/infodancer/maildancer/internal/imapd/metrics"
)

// Session implements imapserver.Session backed by go-maildir.
type Session struct {
	conn        *imapserver.Conn
	cfg         *config.Config
	authRouter  *domain.AuthRouter
	username    string
	mailboxBase string // base dir for user (from User.Mailbox)
	userDomain  string
	collector   metrics.Collector
	logger      *slog.Logger

	// Selected state
	selectedMailbox string
	selectedDir     maildir.Dir
	messages        []*maildir.Message
	tracker         *imapserver.MailboxTracker
	sessionTracker  *imapserver.SessionTracker
	readOnly        bool
}

// NewSession creates a new IMAP session for the given connection.
func NewSession(conn *imapserver.Conn, cfg *config.Config, authRouter *domain.AuthRouter, collector metrics.Collector, logger *slog.Logger) *Session {
	return &Session{
		conn:       conn,
		cfg:        cfg,
		authRouter: authRouter,
		collector:  collector,
		logger:     logging.WithConnection(logger, conn.NetConn().RemoteAddr().String()),
	}
}

// Login authenticates the user.
func (s *Session) Login(username, password string) error {
	ctx := context.Background()
	result, err := s.authRouter.AuthenticateWithDomain(ctx, username, password)
	if err != nil {
		s.logger.Info("login failed", "username", username, "error", err)
		s.collector.AuthAttempt(extractDomain(username), false)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Authentication failed",
		}
	}
	s.username = username
	s.userDomain = extractDomain(username)
	s.mailboxBase = result.Session.User.Mailbox
	s.collector.AuthAttempt(s.userDomain, true)
	s.logger.Info("login success", "username", username)
	return nil
}

// Select opens a mailbox.
func (s *Session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	dir, err := s.maildirForMailbox(mailbox)
	if err != nil {
		return nil, err
	}
	if err := dir.Init(); err != nil && !os.IsExist(err) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "No such mailbox"}
	}

	msgs, err := dir.Messages()
	if err != nil {
		return nil, err
	}

	// Cleanup old tracker
	s.unselect()

	s.selectedMailbox = mailbox
	s.selectedDir = dir
	s.messages = msgs
	s.readOnly = options != nil && options.ReadOnly

	tracker := imapserver.NewMailboxTracker(uint32(len(msgs)))
	s.tracker = tracker
	s.sessionTracker = tracker.NewSession()

	// Count recent (new/ subdir) and find first unseen
	recentCount := countNewMessages(dir)
	var firstUnseen uint32
	for i, msg := range msgs {
		if !hasMaildirFlag(msg, maildir.FlagSeen) {
			if firstUnseen == 0 {
				firstUnseen = uint32(i + 1)
			}
		}
	}

	s.collector.FolderSelected(s.userDomain)

	return &imap.SelectData{
		Flags:             []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft},
		PermanentFlags:    []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft},
		NumMessages:       uint32(len(msgs)),
		NumRecent:         recentCount,
		FirstUnseenSeqNum: firstUnseen,
		UIDValidity:       s.uidValidity(dir),
		UIDNext:           imap.UID(len(msgs) + 1),
	}, nil
}

// Create creates a new mailbox.
func (s *Session) Create(mailbox string, _ *imap.CreateOptions) error {
	dir, err := s.maildirForMailbox(mailbox)
	if err != nil {
		return err
	}
	return dir.Init()
}

// Delete removes a mailbox.
func (s *Session) Delete(mailbox string) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Cannot delete INBOX"}
	}
	dir, err := s.maildirForMailbox(mailbox)
	if err != nil {
		return err
	}
	return os.RemoveAll(string(dir))
}

// Rename renames a mailbox.
func (s *Session) Rename(mailbox, newName string, _ *imap.RenameOptions) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Cannot rename INBOX"}
	}
	oldDir, err := s.maildirForMailbox(mailbox)
	if err != nil {
		return err
	}
	newDir, err := s.maildirForMailbox(newName)
	if err != nil {
		return err
	}
	return os.Rename(string(oldDir), string(newDir))
}

// Subscribe is a no-op (maildir has no subscription state).
func (s *Session) Subscribe(_ string) error {
	return nil
}

// Unsubscribe is a no-op.
func (s *Session) Unsubscribe(_ string) error {
	return nil
}

// List lists mailboxes matching the given patterns.
func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	// Collect all mailbox names
	var mailboxes []string
	mailboxes = append(mailboxes, "INBOX")

	// List subdirectories (dot-prefixed folders)
	if s.mailboxBase != "" {
		entries, err := os.ReadDir(s.mailboxBase)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), ".") {
					name := strings.TrimPrefix(entry.Name(), ".")
					if name != "" {
						mailboxes = append(mailboxes, name)
					}
				}
			}
		}
	}

	for _, mbox := range mailboxes {
		for _, pattern := range patterns {
			if imapserver.MatchList(mbox, '.', ref, pattern) {
				if err := w.WriteList(&imap.ListData{
					Mailbox: mbox,
					Delim:   '.',
				}); err != nil {
					return err
				}
				break
			}
		}
	}

	return nil
}

// Status returns mailbox status data.
func (s *Session) Status(mailbox string, options *imap.StatusOptions) (*imap.StatusData, error) {
	dir, err := s.maildirForMailbox(mailbox)
	if err != nil {
		return nil, err
	}
	msgs, err := dir.Messages()
	if err != nil {
		return nil, err
	}

	data := &imap.StatusData{
		Mailbox: mailbox,
	}

	if options.NumMessages {
		n := uint32(len(msgs))
		data.NumMessages = &n
	}

	if options.UIDNext {
		data.UIDNext = imap.UID(len(msgs) + 1)
	}

	if options.UIDValidity {
		data.UIDValidity = s.uidValidity(dir)
	}

	if options.NumUnseen {
		var count uint32
		for _, msg := range msgs {
			if !hasMaildirFlag(msg, maildir.FlagSeen) {
				count++
			}
		}
		data.NumUnseen = &count
	}

	if options.NumRecent {
		n := countNewMessages(dir)
		data.NumRecent = &n
	}

	return data, nil
}

// Append adds a message to a mailbox.
func (s *Session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	dir, err := s.maildirForMailbox(mailbox)
	if err != nil {
		return nil, err
	}
	if err := dir.Init(); err != nil && !os.IsExist(err) {
		return nil, err
	}

	delivery, err := maildir.NewDelivery(string(dir))
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(delivery, r); err != nil {
		_ = delivery.Abort()
		return nil, err
	}

	if err := delivery.Close(); err != nil {
		return nil, err
	}

	// Set flags if provided
	if options != nil && len(options.Flags) > 0 {
		msgs, err := dir.Messages()
		if err == nil && len(msgs) > 0 {
			lastMsg := msgs[len(msgs)-1]
			var mdFlags []maildir.Flag
			for _, f := range options.Flags {
				if mf, ok := imapFlagToMaildir(f); ok {
					mdFlags = append(mdFlags, mf)
				}
			}
			if len(mdFlags) > 0 {
				_ = lastMsg.SetFlags(mdFlags)
			}
		}
	}

	s.collector.MessageStored(s.userDomain)

	// Get updated message count for UID
	msgs, _ := dir.Messages()
	uid := imap.UID(len(msgs))

	return &imap.AppendData{
		UIDValidity: s.uidValidity(dir),
		UID:         uid,
	}, nil
}

// Poll checks for mailbox updates.
func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.sessionTracker == nil {
		return nil
	}
	return s.sessionTracker.Poll(w, allowExpunge)
}

// Idle waits for mailbox updates.
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	if s.sessionTracker == nil {
		return nil
	}
	return s.sessionTracker.Idle(w, stop)
}

// Unselect closes the currently selected mailbox without expunging.
func (s *Session) Unselect() error {
	s.unselect()
	return nil
}

// Expunge permanently removes messages marked for deletion.
func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if s.messages == nil {
		return nil
	}

	// Walk in reverse to maintain correct sequence numbers
	for i := len(s.messages) - 1; i >= 0; i-- {
		msg := s.messages[i]
		uid := imap.UID(i + 1)

		// Check if restricted to specific UIDs
		if uids != nil && !uids.Contains(uid) {
			continue
		}

		// Only expunge messages with \Deleted flag
		if !hasMaildirFlag(msg, maildir.FlagTrashed) {
			continue
		}

		seqNum := uint32(i + 1)
		if err := msg.Remove(); err != nil {
			s.logger.Error("expunge failed", "key", msg.Key(), "error", err)
			continue
		}

		if err := w.WriteExpunge(seqNum); err != nil {
			return err
		}

		if s.tracker != nil {
			s.tracker.QueueExpunge(seqNum)
		}

		s.collector.MessageExpunged(s.userDomain)
	}

	// Reload messages
	msgs, err := s.selectedDir.Messages()
	if err != nil {
		return err
	}
	s.messages = msgs

	return nil
}

// Search searches for messages matching the criteria.
func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, _ *imap.SearchOptions) (*imap.SearchData, error) {
	if s.messages == nil {
		return &imap.SearchData{}, nil
	}

	var matchedSeqs imap.SeqSet
	var matchedUIDs imap.UIDSet

	for i, msg := range s.messages {
		seqNum := uint32(i + 1)
		uid := imap.UID(i + 1)

		if !s.matchesCriteria(msg, seqNum, uid, criteria) {
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

// Fetch retrieves message data.
func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	indices := s.resolveNumSet(numSet)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		msg := s.messages[idx]
		seqNum := uint32(idx + 1)
		uid := imap.UID(idx + 1)

		if err := s.fetchMessage(w, msg, seqNum, uid, options); err != nil {
			return err
		}
	}

	return nil
}

// Store modifies message flags.
func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	indices := s.resolveNumSet(numSet)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		msg := s.messages[idx]
		seqNum := uint32(idx + 1)
		uid := imap.UID(idx + 1)

		currentFlags := msg.Flags()
		newFlags := applyStoreFlags(currentFlags, flags)

		if err := msg.SetFlags(newFlags); err != nil {
			return err
		}

		if !flags.Silent {
			imapFlags := maildirFlagsToIMAP(newFlags)

			respW := w.CreateMessage(seqNum)
			respW.WriteUID(uid)
			respW.WriteFlags(imapFlags)
			if err := respW.Close(); err != nil {
				return err
			}

			if s.tracker != nil {
				s.tracker.QueueMessageFlags(seqNum, uid, imapFlags, s.sessionTracker)
			}
		}
	}

	return nil
}

// Copy copies messages to another mailbox.
func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	destDir, err := s.maildirForMailbox(dest)
	if err != nil {
		return nil, err
	}
	if err := destDir.Init(); err != nil && !os.IsExist(err) {
		return nil, err
	}

	indices := s.resolveNumSet(numSet)

	var srcUIDs imap.UIDSet
	var destUIDs imap.UIDSet

	// Get current count for UID assignment
	destMsgs, _ := destDir.Messages()
	nextUID := imap.UID(len(destMsgs) + 1)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		msg := s.messages[idx]
		uid := imap.UID(idx + 1)

		if _, err := msg.CopyTo(destDir); err != nil {
			return nil, err
		}

		srcUIDs.AddNum(uid)
		destUIDs.AddNum(nextUID)
		nextUID++
	}

	return &imap.CopyData{
		UIDValidity: s.uidValidity(destDir),
		SourceUIDs:  srcUIDs,
		DestUIDs:    destUIDs,
	}, nil
}

// Close ends the session and releases resources.
func (s *Session) Close() error {
	s.unselect()
	s.collector.ConnectionClosed()
	return nil
}

// --- Internal helpers ---

func (s *Session) unselect() {
	if s.sessionTracker != nil {
		s.sessionTracker.Close()
		s.sessionTracker = nil
	}
	s.tracker = nil
	s.messages = nil
	s.selectedMailbox = ""
}

// maildirForMailbox resolves a mailbox name to a maildir.Dir, validating that
// the resulting path stays within the user's mailbox base directory.
func (s *Session) maildirForMailbox(mailbox string) (maildir.Dir, error) {
	if strings.EqualFold(mailbox, "INBOX") {
		return maildir.Dir(s.mailboxBase), nil
	}

	base, err := filepath.Abs(s.mailboxBase)
	if err != nil {
		return "", err
	}
	target := filepath.Join(base, "."+mailbox)

	// Ensure the resolved path is still under the user's base directory.
	rel, err := filepath.Rel(base, target)
	if err != nil || strings.HasPrefix(rel, "..") || strings.Contains(rel, string(filepath.Separator)+"..") {
		return "", &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}

	return maildir.Dir(target), nil
}

func (s *Session) uidValidity(dir maildir.Dir) uint32 {
	h := fnv.New32a()
	h.Write([]byte(string(dir)))
	v := h.Sum32()
	if v == 0 {
		return 1
	}
	return v
}

func (s *Session) resolveNumSet(numSet imap.NumSet) []int {
	var indices []int

	switch ns := numSet.(type) {
	case imap.SeqSet:
		nums, ok := ns.Nums()
		if !ok {
			// Dynamic set with "*" - include all
			for i := range s.messages {
				indices = append(indices, i)
			}
			return indices
		}
		for _, n := range nums {
			indices = append(indices, int(n)-1)
		}
	case imap.UIDSet:
		uids, ok := ns.Nums()
		if !ok {
			for i := range s.messages {
				indices = append(indices, i)
			}
			return indices
		}
		for _, u := range uids {
			indices = append(indices, int(u)-1)
		}
	}

	return indices
}

func (s *Session) fetchMessage(w *imapserver.FetchWriter, msg *maildir.Message, seqNum uint32, uid imap.UID, options *imap.FetchOptions) error {
	respW := w.CreateMessage(seqNum)

	if options.UID {
		respW.WriteUID(uid)
	}

	if options.Flags {
		respW.WriteFlags(maildirFlagsToIMAP(msg.Flags()))
	}

	// Read message content if needed for envelope, body sections, size, or body structure
	var content []byte
	needContent := options.Envelope || options.RFC822Size || options.InternalDate || len(options.BodySection) > 0 || options.BodyStructure != nil

	if needContent {
		r, err := msg.Open()
		if err != nil {
			_ = respW.Close()
			return err
		}
		content, err = io.ReadAll(r)
		r.Close()
		if err != nil {
			_ = respW.Close()
			return err
		}
	}

	if options.RFC822Size {
		respW.WriteRFC822Size(int64(len(content)))
		s.collector.MessageFetched(s.userDomain, int64(len(content)))
	}

	if options.InternalDate {
		info, err := os.Stat(msg.Filename())
		if err == nil {
			respW.WriteInternalDate(info.ModTime())
		}
	}

	if options.Envelope {
		hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(content)))
		if err == nil {
			respW.WriteEnvelope(imapserver.ExtractEnvelope(hdr))
		}
	}

	if options.BodyStructure != nil {
		respW.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(content)))
	}

	// Handle body sections
	markSeen := false
	for _, section := range options.BodySection {
		sectionData := imapserver.ExtractBodySection(bytes.NewReader(content), section)
		wc := respW.WriteBodySection(section, int64(len(sectionData)))
		_, _ = wc.Write(sectionData)
		_ = wc.Close()

		if !section.Peek {
			markSeen = true
		}
	}

	// Mark as seen if a non-PEEK body section was fetched
	if markSeen && !s.readOnly {
		if !hasMaildirFlag(msg, maildir.FlagSeen) {
			currentFlags := msg.Flags()
			currentFlags = append(currentFlags, maildir.FlagSeen)
			_ = msg.SetFlags(currentFlags)
		}
	}

	return respW.Close()
}

func (s *Session) matchesCriteria(msg *maildir.Message, seqNum uint32, uid imap.UID, criteria *imap.SearchCriteria) bool {
	// Check sequence number sets
	for _, ss := range criteria.SeqNum {
		if !ss.Contains(seqNum) {
			return false
		}
	}

	// Check UID sets
	for _, us := range criteria.UID {
		if !us.Contains(uid) {
			return false
		}
	}

	// Check required flags
	for _, reqFlag := range criteria.Flag {
		mf, ok := imapFlagToMaildir(reqFlag)
		if !ok {
			return false
		}
		if !hasMaildirFlag(msg, mf) {
			return false
		}
	}

	// Check not-flags
	for _, notFlag := range criteria.NotFlag {
		mf, ok := imapFlagToMaildir(notFlag)
		if ok && hasMaildirFlag(msg, mf) {
			return false
		}
	}

	// Check size criteria
	if criteria.Larger > 0 || criteria.Smaller > 0 {
		info, err := os.Stat(msg.Filename())
		if err != nil {
			return false
		}
		if criteria.Larger > 0 && info.Size() <= criteria.Larger {
			return false
		}
		if criteria.Smaller > 0 && info.Size() >= criteria.Smaller {
			return false
		}
	}

	// Check arrival date criteria using file modification time
	if !criteria.Since.IsZero() || !criteria.Before.IsZero() {
		info, err := os.Stat(msg.Filename())
		if err != nil {
			return false
		}
		mtime := info.ModTime().Truncate(24 * time.Hour)
		if !criteria.Since.IsZero() && mtime.Before(criteria.Since.Truncate(24*time.Hour)) {
			return false
		}
		if !criteria.Before.IsZero() && !mtime.Before(criteria.Before.Truncate(24*time.Hour)) {
			return false
		}
	}

	// Check sent date, header, body, and text criteria — require opening the message
	needContent := !criteria.SentSince.IsZero() || !criteria.SentBefore.IsZero() ||
		len(criteria.Header) > 0 || len(criteria.Body) > 0 || len(criteria.Text) > 0
	if needContent {
		r, err := msg.Open()
		if err != nil {
			return false
		}
		content, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return false
		}

		// Parse headers for sent date and header field checks
		hdr, hdrErr := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(content)))

		// Sent date criteria
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
				// No parseable Date header — exclude from date-based searches
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

		// Header field criteria
		for _, hf := range criteria.Header {
			if hdrErr != nil {
				return false
			}
			val := hdr.Get(hf.Key)
			if !strings.Contains(strings.ToLower(val), strings.ToLower(hf.Value)) {
				return false
			}
		}

		// Body and Text criteria (case-insensitive substring match)
		contentStr := strings.ToLower(string(content))
		for _, term := range criteria.Body {
			// Body searches message body only; use full content as approximation
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

	// Check NOT criteria
	for _, not := range criteria.Not {
		if s.matchesCriteria(msg, seqNum, uid, &not) {
			return false
		}
	}

	// Check OR criteria
	for _, or := range criteria.Or {
		if !s.matchesCriteria(msg, seqNum, uid, &or[0]) && !s.matchesCriteria(msg, seqNum, uid, &or[1]) {
			return false
		}
	}

	return true
}

// countNewMessages returns the number of messages in the maildir new/ subdirectory,
// which is the Maildir analog of the IMAP \Recent flag.
func countNewMessages(dir maildir.Dir) uint32 {
	entries, err := os.ReadDir(filepath.Join(string(dir), "new"))
	if err != nil {
		return 0
	}
	var count uint32
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	return count
}

// --- Flag conversion helpers ---

func maildirFlagToIMAP(f maildir.Flag) imap.Flag {
	switch f {
	case maildir.FlagSeen:
		return imap.FlagSeen
	case maildir.FlagReplied:
		return imap.FlagAnswered
	case maildir.FlagFlagged:
		return imap.FlagFlagged
	case maildir.FlagTrashed:
		return imap.FlagDeleted
	case maildir.FlagDraft:
		return imap.FlagDraft
	}
	return ""
}

func maildirFlagsToIMAP(flags []maildir.Flag) []imap.Flag {
	var result []imap.Flag
	for _, f := range flags {
		if imapFlag := maildirFlagToIMAP(f); imapFlag != "" {
			result = append(result, imapFlag)
		}
	}
	return result
}

func imapFlagToMaildir(f imap.Flag) (maildir.Flag, bool) {
	switch f {
	case imap.FlagSeen:
		return maildir.FlagSeen, true
	case imap.FlagAnswered:
		return maildir.FlagReplied, true
	case imap.FlagFlagged:
		return maildir.FlagFlagged, true
	case imap.FlagDeleted:
		return maildir.FlagTrashed, true
	case imap.FlagDraft:
		return maildir.FlagDraft, true
	}
	return 0, false
}

func hasMaildirFlag(msg *maildir.Message, flag maildir.Flag) bool {
	for _, f := range msg.Flags() {
		if f == flag {
			return true
		}
	}
	return false
}

func applyStoreFlags(current []maildir.Flag, store *imap.StoreFlags) []maildir.Flag {
	switch store.Op {
	case imap.StoreFlagsSet:
		var result []maildir.Flag
		for _, f := range store.Flags {
			if mf, ok := imapFlagToMaildir(f); ok {
				result = append(result, mf)
			}
		}
		return result

	case imap.StoreFlagsAdd:
		result := make([]maildir.Flag, len(current))
		copy(result, current)
		for _, f := range store.Flags {
			mf, ok := imapFlagToMaildir(f)
			if !ok {
				continue
			}
			found := false
			for _, existing := range result {
				if existing == mf {
					found = true
					break
				}
			}
			if !found {
				result = append(result, mf)
			}
		}
		return result

	case imap.StoreFlagsDel:
		var result []maildir.Flag
		for _, existing := range current {
			remove := false
			for _, f := range store.Flags {
				mf, ok := imapFlagToMaildir(f)
				if ok && existing == mf {
					remove = true
					break
				}
			}
			if !remove {
				result = append(result, existing)
			}
		}
		return result
	}

	return current
}

func extractDomain(username string) string {
	if idx := strings.LastIndex(username, "@"); idx >= 0 {
		return username[idx+1:]
	}
	return "local"
}
