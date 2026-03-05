package backend

import (
	"context"
	"sort"
	"strings"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// Expunge permanently removes messages marked for deletion.
func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	if s.messages == nil {
		return nil
	}
	ctx := context.Background()

	var anyExpunged bool
	for i := len(s.messages) - 1; i >= 0; i-- {
		info := s.messages[i]
		uid := imap.UID(i + 1)

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

		if err := w.WriteExpunge(seqNum); err != nil {
			return err
		}
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
		uid := imap.UID(idx + 1)

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
func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	if s.folderStore == nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Copy not supported"}
	}
	if !isValidMailboxName(dest) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}

	ctx := context.Background()
	destMsgs, _ := s.listMessages(ctx, dest)
	nextDestUID := imap.UID(len(destMsgs) + 1)

	indices := s.resolveNumSet(numSet)
	var srcUIDs imap.UIDSet
	var destUIDs imap.UIDSet

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		info := s.messages[idx]
		srcUID := imap.UID(idx + 1)

		if _, err := s.folderStore.CopyMessage(ctx, s.mailbox, s.selectedMailbox, info.UID, dest); err != nil {
			return nil, err
		}

		srcUIDs.AddNum(srcUID)
		destUIDs.AddNum(nextDestUID)
		nextDestUID++
	}

	return &imap.CopyData{
		UIDValidity: s.getUIDValidity(ctx, dest),
		SourceUIDs:  srcUIDs,
		DestUIDs:    destUIDs,
	}, nil
}

// mover is satisfied by SubprocessStore when mail-session supports MOVE.
// The method signature matches SubprocessStore.MoveMessage exactly.
type mover interface {
	MoveMessage(ctx context.Context, mailbox, srcFolder, uid, destFolder string) (string, error)
}

// Move implements imapserver.SessionMove (RFC 6851). Advertising IMAP MOVE
// capability requires implementing this interface; go-imap/v2 advertises the
// capability automatically when the session satisfies SessionMove.
//
// If the underlying store is a SubprocessStore (i.e. mail-session is in use),
// the MOVE is handled atomically there — including rspamd Junk-folder learning.
// Otherwise we fall back to Copy + mark-\Deleted + Expunge, with direct
// rspamd learning when a spamLearner is configured.
func (s *Session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Move not supported"}
	}
	if !strings.EqualFold(dest, "INBOX") && !isValidMailboxName(dest) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}

	ctx := context.Background()
	mv, hasMover := s.folderStore.(mover)

	destMsgs, _ := s.listMessages(ctx, dest)
	nextDestUID := imap.UID(len(destMsgs) + 1)

	indices := s.resolveNumSet(numSet)
	sort.Ints(indices)

	var srcUIDs, destUIDs imap.UIDSet

	srcFolder := s.selectedMailbox
	isJunkSrc := strings.EqualFold(srcFolder, "Junk")
	isJunkDest := strings.EqualFold(dest, "Junk")

	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		info := s.messages[idx]
		srcUID := imap.UID(idx + 1)

		if hasMover {
			// SubprocessStore handles MOVE atomically, including rspamd learning.
			if _, err := mv.MoveMessage(ctx, s.mailbox, srcFolder, info.UID, dest); err != nil {
				return err
			}
		} else {
			// Fallback: Copy + Delete. Trigger direct rspamd learn when
			// crossing the Junk boundary and a learner is configured.
			if s.learner != nil && (isJunkSrc || isJunkDest) && isJunkSrc != isJunkDest {
				s.triggerLearn(ctx, srcFolder, info.UID, isJunkDest)
			}

			if _, err := s.folderStore.CopyMessage(ctx, s.mailbox, srcFolder, info.UID, dest); err != nil {
				return err
			}
			if err := s.deleteMessage(ctx, srcFolder, info.UID); err != nil {
				return err
			}
		}

		srcUIDs.AddNum(srcUID)
		destUIDs.AddNum(nextDestUID)
		nextDestUID++
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

	// Write expunge notifications in descending seqnum order so client seqnums
	// remain valid as each expunge is applied.
	for i := len(indices) - 1; i >= 0; i-- {
		idx := indices[i]
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		seqNum := uint32(idx + 1)
		if err := w.WriteExpunge(seqNum); err != nil {
			return err
		}
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

	return nil
}

// triggerLearn reads a message from the source folder and sends it to rspamd
// for Bayes training. Errors are logged but do not fail the MOVE operation.
func (s *Session) triggerLearn(ctx context.Context, srcFolder, uid string, toJunk bool) {
	rc, err := s.folderStore.RetrieveFromFolder(ctx, s.mailbox, srcFolder, uid)
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

func learnDirection(toJunk bool) string {
	if toJunk {
		return "spam"
	}
	return "ham"
}
