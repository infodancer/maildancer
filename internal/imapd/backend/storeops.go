package backend

import (
	"context"
	"sort"
	"strings"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// Expunge permanently removes messages marked for deletion.
//
// It does not write EXPUNGE responses via the ExpungeWriter directly: it only
// queues them on the mailbox tracker. go-imap runs Session.Poll after the
// command (before the tagged OK), which drains the tracker and emits each
// EXPUNGE exactly once. Writing them here as well produced duplicate
// "* n EXPUNGE" responses -- see issue #132.
func (s *Session) Expunge(_ *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if s.messages == nil {
		return nil
	}
	ctx := context.Background()

	var anyExpunged bool
	for i := len(s.messages) - 1; i >= 0; i-- {
		info := s.messages[i]
		uid := imap.UID(info.UID)

		if uids != nil && !uids.Contains(uid) {
			continue
		}
		if !hasFlag(info.Flags, imap.FlagDeleted) {
			continue
		}

		seqNum := uint32(i + 1)
		if err := s.deleteMessage(ctx, s.selectedMailbox, info.UID); err != nil {
			s.logger.Error("expunge delete failed", "uid", info.UID, "error", err)
			continue
		}

		// Queue the expunge for the post-command poll to emit; do not write it
		// here as well (that double-emitted, #132).
		if s.tracker != nil {
			s.tracker.QueueExpunge(seqNum)
		}
		s.collector.MessageExpunged(s.userDomain)
		anyExpunged = true
	}

	if anyExpunged {
		if err := s.expungeMailbox(ctx, s.selectedMailbox); err != nil {
			return err
		}
		msgs, err := s.listMessages(ctx, s.selectedMailbox)
		if err != nil {
			return err
		}
		s.messages = msgs
		s.buildUIDIndex()
	}

	return nil
}

// Store modifies message flags.
func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Flag operations not supported"}
	}
	ctx := context.Background()
	indices := s.resolveNumSet(numSet)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		info := s.messages[idx]
		seqNum := uint32(idx + 1)
		uid := imap.UID(info.UID)

		newFlags := applyStoreFlagsStr(info.Flags, flags)
		if err := s.folderStore.SetFlagsInFolder(ctx, s.mailbox, s.selectedMailbox, info.UID, newFlags); err != nil {
			return err
		}
		s.messages[idx].Flags = newFlags

		if !flags.Silent {
			imapFlags := make([]imap.Flag, len(newFlags))
			for i, f := range newFlags {
				imapFlags[i] = imap.Flag(f)
			}

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
// When copying across the Junk boundary and a learner is configured,
// spam/ham learning is triggered (clients that use COPY+DELETE instead of MOVE).
func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	if s.folderStore == nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Copy not supported"}
	}
	if !strings.EqualFold(dest, "INBOX") && !isValidMailboxName(dest) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}

	ctx := context.Background()

	srcFolder := s.selectedMailbox
	junkFolder := s.junkFolderName()
	isJunkSrc := strings.EqualFold(srcFolder, junkFolder)
	isJunkDest := strings.EqualFold(dest, junkFolder)

	indices := s.resolveNumSet(numSet)
	var srcUIDs imap.UIDSet
	var destUIDs imap.UIDSet

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		info := s.messages[idx]
		srcUID := imap.UID(info.UID)

		if s.learner != nil && (isJunkSrc || isJunkDest) && isJunkSrc != isJunkDest {
			s.triggerLearn(ctx, srcFolder, info.UID, isJunkDest)
		}

		newUID, err := s.folderStore.CopyMessage(ctx, s.mailbox, s.selectedMailbox, info.UID, dest)
		if err != nil {
			return nil, err
		}

		srcUIDs.AddNum(srcUID)
		destUIDs.AddNum(imap.UID(newUID))
	}

	return &imap.CopyData{
		UIDValidity: s.getUIDValidity(ctx, dest),
		SourceUIDs:  srcUIDs,
		DestUIDs:    destUIDs,
	}, nil
}

// mover is satisfied by grpcStore (via embedded client.Client.MoveMessage).
// The method signature matches client.Client.MoveMessage exactly.
type mover interface {
	MoveMessage(ctx context.Context, mailbox, srcFolder string, uid uint32, destFolder string) (uint32, error)
}

// Move implements imapserver.SessionMove (RFC 6851). Advertising IMAP MOVE
// capability requires implementing this interface; go-imap/v2 advertises the
// capability automatically when the session satisfies SessionMove.
//
// If the underlying store satisfies the mover interface (grpcStore via
// mail-session), the MOVE is handled atomically -- including rspamd Junk-folder
// learning. Otherwise we fall back to Copy + mark-\Deleted + Expunge, with
// direct rspamd learning when a spamLearner is configured.
func (s *Session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Move not supported"}
	}
	if !strings.EqualFold(dest, "INBOX") && !isValidMailboxName(dest) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}

	ctx := context.Background()
	mv, hasMover := s.folderStore.(mover)

	indices := s.resolveNumSet(numSet)
	sort.Ints(indices)

	var srcUIDs, destUIDs imap.UIDSet

	srcFolder := s.selectedMailbox
	junkFolder := s.junkFolderName()
	isJunkSrc := strings.EqualFold(srcFolder, junkFolder)
	isJunkDest := strings.EqualFold(dest, junkFolder)

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		info := s.messages[idx]
		srcUID := imap.UID(info.UID)

		// Trigger rspamd learn when crossing the Junk boundary.
		// This must happen before the move so the message can be read from
		// the source folder.
		if s.learner != nil && (isJunkSrc || isJunkDest) && isJunkSrc != isJunkDest {
			s.triggerLearn(ctx, srcFolder, info.UID, isJunkDest)
		}

		var newUID uint32
		if hasMover {
			var err error
			newUID, err = mv.MoveMessage(ctx, s.mailbox, srcFolder, info.UID, dest)
			if err != nil {
				return err
			}
		} else {
			var err error
			newUID, err = s.folderStore.CopyMessage(ctx, s.mailbox, srcFolder, info.UID, dest)
			if err != nil {
				return err
			}
			if err := s.deleteMessage(ctx, srcFolder, info.UID); err != nil {
				return err
			}
		}

		srcUIDs.AddNum(srcUID)
		destUIDs.AddNum(imap.UID(newUID))
	}

	// Fallback path needs an explicit expunge; mover already expunged atomically.
	if !hasMover && len(indices) > 0 {
		if err := s.expungeMailbox(ctx, srcFolder); err != nil {
			return err
		}
	}

	if err := w.WriteCopyData(&imap.CopyData{
		UIDValidity: s.getUIDValidity(ctx, dest),
		SourceUIDs:  srcUIDs,
		DestUIDs:    destUIDs,
	}); err != nil {
		return err
	}

	// Queue expunges in descending seqnum order so client seqnums remain valid
	// as each expunge is applied. go-imap's post-command poll drains the tracker
	// and emits each "* n EXPUNGE" exactly once, after this COPYUID and before
	// the tagged OK -- the RFC 6851 order. Writing them here as well
	// double-emitted (#132).
	for i := len(indices) - 1; i >= 0; i-- {
		idx := indices[i]
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		seqNum := uint32(idx + 1)
		if s.tracker != nil {
			s.tracker.QueueExpunge(seqNum)
		}
		s.collector.MessageExpunged(s.userDomain)
	}

	msgs, err := s.listMessages(ctx, srcFolder)
	if err != nil {
		return err
	}
	s.messages = msgs
	s.buildUIDIndex()

	return nil
}

// triggerLearn reads a message from the source folder and sends it to rspamd
// for Bayes training. Errors are logged but do not fail the MOVE operation.
func (s *Session) triggerLearn(ctx context.Context, srcFolder string, uid uint32, toJunk bool) {
	rc, err := s.retrieveMessage(ctx, srcFolder, uid)
	if err != nil {
		s.logger.Warn("spam learn: failed to retrieve message",
			"uid", uid, "folder", srcFolder, "error", err)
		return
	}
	defer func() { _ = rc.Close() }()

	var learnErr error
	if toJunk {
		learnErr = s.learner.learnSpam(ctx, s.username, rc)
	} else {
		learnErr = s.learner.learnHam(ctx, s.username, rc)
	}
	if learnErr != nil {
		s.logger.Warn("spam learn: rspamd call failed",
			"uid", uid, "direction", learnDirection(toJunk), "error", learnErr)
	} else {
		s.logger.Debug("spam learn: trained",
			"uid", uid, "direction", learnDirection(toJunk), "user", s.username)
	}
}

// junkFolderName returns the configured Junk folder name, defaulting to "Junk".
func (s *Session) junkFolderName() string {
	if s.cfg != nil && s.cfg.Rspamd.JunkFolder != "" {
		return s.cfg.Rspamd.JunkFolder
	}
	return "Junk"
}

func learnDirection(toJunk bool) string {
	if toJunk {
		return "spam"
	}
	return "ham"
}
