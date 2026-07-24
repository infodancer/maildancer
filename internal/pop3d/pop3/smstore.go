package pop3

import (
	"context"
	"io"

	"github.com/infodancer/maildancer/internal/smclient"
	"github.com/infodancer/maildancer/msgstore"
)

// Compile-time assertions.
var (
	_ msgstore.MessageStore = (*sessionManagerStore)(nil)
	_ io.Closer             = (*sessionManagerStore)(nil)
)

// sessionManagerStore adapts a SessionManagerClient into a msgstore.MessageStore.
// All operations are proxied through the session-manager's MailboxService using
// the session token obtained during Login. Closing the store calls Logout.
type sessionManagerStore struct {
	sess *smclient.Session
}

// newSessionManagerStore creates a store backed by the given client and session token.
func newSessionManagerStore(sess *smclient.Session) *sessionManagerStore {
	return &sessionManagerStore{sess: sess}
}

func (s *sessionManagerStore) List(ctx context.Context, mailbox string) ([]msgstore.MessageInfo, error) {
	msgs, err := s.sess.ListMessages(ctx, "")
	if err != nil {
		return nil, err
	}
	result := make([]msgstore.MessageInfo, len(msgs))
	for i, m := range msgs {
		result[i] = msgstore.MessageInfo{
			UID:  m.Uid,
			Size: m.Size,
		}
	}
	return result, nil
}

func (s *sessionManagerStore) Stat(ctx context.Context, mailbox string) (int, int64, error) {
	count, totalBytes, err := s.sess.StatMailbox(ctx, "")
	if err != nil {
		return 0, 0, err
	}
	return int(count), totalBytes, nil
}

func (s *sessionManagerStore) Retrieve(ctx context.Context, mailbox string, uid uint32) (io.ReadCloser, error) {
	return s.sess.FetchMessage(ctx, "", uid)
}

func (s *sessionManagerStore) Delete(ctx context.Context, mailbox string, uid uint32) error {
	return s.sess.Delete(ctx, uid)
}

func (s *sessionManagerStore) Expunge(ctx context.Context, mailbox string) error {
	return s.sess.ExpungeMailbox(ctx, "")
}

// Close releases the session by calling Logout on the session-manager.
func (s *sessionManagerStore) Close() error {
	return s.sess.Logout(context.Background())
}
