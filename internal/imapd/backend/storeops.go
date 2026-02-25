package backend

import (
	"context"

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
