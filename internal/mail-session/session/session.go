// Package session manages the per-connection mailbox state for mail-session.
package session

import (
	"context"
	"fmt"

	mserrors "github.com/infodancer/maildancer/internal/mail-session/errors"
	"github.com/infodancer/maildancer/msgstore"
)

// Session holds the state for a single mail-session connection:
// the selected mailbox, the cached message list, and pending deletion marks.
type Session struct {
	store   msgstore.MessageStore
	mailbox string
	msgs    []msgstore.MessageInfo
	deleted map[string]struct{}
}

// New returns a Session backed by the given MessageStore.
func New(store msgstore.MessageStore) *Session {
	return &Session{
		store:   store,
		deleted: make(map[string]struct{}),
	}
}

// Open selects a mailbox and caches its message list.
func (s *Session) Open(ctx context.Context, mailbox string) error {
	msgs, err := s.store.List(ctx, mailbox)
	if err != nil {
		return fmt.Errorf("open mailbox %q: %w", mailbox, err)
	}
	s.mailbox = mailbox
	s.msgs = msgs
	s.deleted = make(map[string]struct{})
	return nil
}

// Mailbox returns the currently open mailbox name.
func (s *Session) Mailbox() string {
	return s.mailbox
}

// List returns the cached message metadata.
func (s *Session) List() []msgstore.MessageInfo {
	return s.msgs
}

// Stat returns the count and total byte size of all messages in the cache.
func (s *Session) Stat() (count int, totalBytes int64) {
	for i := range s.msgs {
		totalBytes += s.msgs[i].Size
	}
	return len(s.msgs), totalBytes
}

// GetUID finds a message by UID in the cache. Returns ErrMessageNotFound if absent.
func (s *Session) GetUID(uid string) (*msgstore.MessageInfo, error) {
	for i := range s.msgs {
		if s.msgs[i].UID == uid {
			return &s.msgs[i], nil
		}
	}
	return nil, mserrors.ErrMessageNotFound
}

// Delete marks a UID for deletion. Returns ErrMessageNotFound or ErrAlreadyDeleted.
func (s *Session) Delete(uid string) error {
	if _, err := s.GetUID(uid); err != nil {
		return err
	}
	if _, marked := s.deleted[uid]; marked {
		return mserrors.ErrAlreadyDeleted
	}
	s.deleted[uid] = struct{}{}
	return nil
}

// Undelete clears a deletion mark. Returns ErrMessageNotFound or ErrNotDeleted.
func (s *Session) Undelete(uid string) error {
	if _, err := s.GetUID(uid); err != nil {
		return err
	}
	if _, marked := s.deleted[uid]; !marked {
		return mserrors.ErrNotDeleted
	}
	delete(s.deleted, uid)
	return nil
}

// Commit calls store.Delete for each marked UID, then store.Expunge.
func (s *Session) Commit(ctx context.Context) error {
	for uid := range s.deleted {
		if err := s.store.Delete(ctx, s.mailbox, uid); err != nil {
			return fmt.Errorf("delete %q: %w", uid, err)
		}
	}
	if len(s.deleted) > 0 {
		if err := s.store.Expunge(ctx, s.mailbox); err != nil {
			return fmt.Errorf("expunge: %w", err)
		}
	}
	return nil
}
