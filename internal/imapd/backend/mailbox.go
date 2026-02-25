package backend

import (
	"context"
	"hash/fnv"
	"io"
	"strings"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/infodancer/maildancer/msgstore"
)

// listMessages returns messages in a mailbox (INBOX or a named folder).
func (s *Session) listMessages(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	if strings.EqualFold(mailbox, "INBOX") {
		return s.store.List(ctx, s.mailbox)
	}
	if s.folderStore == nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.ListInFolder(ctx, s.mailbox, mailbox)
}

// retrieveMessage returns the content of a message by its msgstore UID.
func (s *Session) retrieveMessage(ctx context.Context, mailbox string, uid string) (io.ReadCloser, error) {
	if strings.EqualFold(mailbox, "INBOX") {
		return s.store.Retrieve(ctx, s.mailbox, uid)
	}
	if s.folderStore == nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.RetrieveFromFolder(ctx, s.mailbox, mailbox, uid)
}

// deleteMessage marks a message for deletion (pending Expunge).
func (s *Session) deleteMessage(ctx context.Context, mailbox string, uid string) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return s.store.Delete(ctx, s.mailbox, uid)
	}
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.DeleteInFolder(ctx, s.mailbox, mailbox, uid)
}

// expungeMailbox permanently removes messages marked for deletion.
func (s *Session) expungeMailbox(ctx context.Context, mailbox string) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return s.store.Expunge(ctx, s.mailbox)
	}
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.ExpungeFolder(ctx, s.mailbox, mailbox)
}

// getUIDValidity returns the UIDValidity for a mailbox via folderStore, with
// an fnv32a hash of the name as fallback.
func (s *Session) getUIDValidity(ctx context.Context, mailbox string) uint32 {
	if s.folderStore != nil {
		v, err := s.folderStore.UIDValidity(ctx, s.mailbox, mailbox)
		if err == nil {
			return v
		}
	}
	h := fnv.New32a()
	h.Write([]byte(mailbox))
	v := h.Sum32()
	if v == 0 {
		return 1
	}
	return v
}

// Select opens a mailbox.
func (s *Session) Select(mailbox string, options *imap.SelectOptions) (*imap.SelectData, error) {
	ctx := context.Background()

	msgs, err := s.listMessages(ctx, mailbox)
	if err != nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "No such mailbox"}
	}

	s.unselect()
	s.selectedMailbox = mailbox
	s.messages = msgs
	s.readOnly = options != nil && options.ReadOnly

	tracker := imapserver.NewMailboxTracker(uint32(len(msgs)))
	s.tracker = tracker
	s.sessionTracker = tracker.NewSession()

	var firstUnseen uint32
	for i, msg := range msgs {
		if !hasFlag(msg.Flags, imap.FlagSeen) {
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
		NumRecent:         0,
		FirstUnseenSeqNum: firstUnseen,
		UIDValidity:       s.getUIDValidity(ctx, mailbox),
		UIDNext:           imap.UID(len(msgs) + 1),
	}, nil
}

// Create creates a new mailbox (folder).
func (s *Session) Create(mailbox string, _ *imap.CreateOptions) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "INBOX already exists"}
	}
	if !isValidMailboxName(mailbox) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.CreateFolder(context.Background(), s.mailbox, mailbox)
}

// Delete removes a mailbox.
func (s *Session) Delete(mailbox string) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Cannot delete INBOX"}
	}
	if !isValidMailboxName(mailbox) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.DeleteFolder(context.Background(), s.mailbox, mailbox)
}

// Rename renames a mailbox.
func (s *Session) Rename(mailbox, newName string, _ *imap.RenameOptions) error {
	if strings.EqualFold(mailbox, "INBOX") {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Cannot rename INBOX"}
	}
	if !isValidMailboxName(mailbox) || !isValidMailboxName(newName) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}
	if s.folderStore == nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Folder operations not supported"}
	}
	return s.folderStore.RenameFolder(context.Background(), s.mailbox, mailbox, newName)
}

// List lists mailboxes matching the given patterns.
func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, _ *imap.ListOptions) error {
	ctx := context.Background()
	var mailboxes []string
	mailboxes = append(mailboxes, "INBOX")

	if s.folderStore != nil {
		folders, err := s.folderStore.ListFolders(ctx, s.mailbox)
		if err == nil {
			mailboxes = append(mailboxes, folders...)
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
	ctx := context.Background()
	msgs, err := s.listMessages(ctx, mailbox)
	if err != nil {
		return nil, err
	}

	data := &imap.StatusData{Mailbox: mailbox}

	if options.NumMessages {
		n := uint32(len(msgs))
		data.NumMessages = &n
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(len(msgs) + 1)
	}
	if options.UIDValidity {
		data.UIDValidity = s.getUIDValidity(ctx, mailbox)
	}
	if options.NumUnseen {
		var count uint32
		for _, msg := range msgs {
			if !hasFlag(msg.Flags, imap.FlagSeen) {
				count++
			}
		}
		data.NumUnseen = &count
	}
	if options.NumRecent {
		var n uint32
		data.NumRecent = &n
	}

	return data, nil
}

// Append adds a message to a mailbox.
func (s *Session) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if s.folderStore == nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Append not supported"}
	}
	if !strings.EqualFold(mailbox, "INBOX") && !isValidMailboxName(mailbox) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Invalid mailbox name"}
	}

	ctx := context.Background()

	var flags []string
	internalDate := time.Now()
	if options != nil {
		for _, f := range options.Flags {
			flags = append(flags, string(f))
		}
		if !options.Time.IsZero() {
			internalDate = options.Time
		}
	}

	_, err := s.folderStore.AppendToFolder(ctx, s.mailbox, mailbox, r, flags, internalDate)
	if err != nil {
		return nil, err
	}

	s.collector.MessageStored(s.userDomain)

	msgs, err := s.listMessages(ctx, mailbox)
	if err != nil {
		return nil, err
	}

	return &imap.AppendData{
		UIDValidity: s.getUIDValidity(ctx, mailbox),
		UID:         imap.UID(len(msgs)),
	}, nil
}
