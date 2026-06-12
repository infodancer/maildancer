package maildir

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	mserrors "github.com/infodancer/maildancer/msgstore/errors"
)

// sieveScriptPath returns the filesystem path for a user's Sieve script.
// The script is expected at {basePath}/{expandedMailbox}/.sieve -- adjacent
// to the Maildir directory, in the user's mailbox root.
func (s *MaildirStore) sieveScriptPath(mailbox string) (string, error) {
	expandedMailbox := s.expandMailbox(mailbox)
	candidate := filepath.Join(s.basePath, expandedMailbox, ".sieve")

	cleanBase := filepath.Clean(s.basePath)
	cleanCandidate := filepath.Clean(candidate)
	if !strings.HasPrefix(cleanCandidate+string(filepath.Separator), cleanBase+string(filepath.Separator)) {
		return "", mserrors.ErrPathTraversal
	}

	return cleanCandidate, nil
}

// SieveScript implements msgstore.SieveScriptProvider. It opens the user's
// Sieve script; the error satisfies errors.Is(err, fs.ErrNotExist) when no
// script exists. Execution happens in the delivery pipeline, not here.
func (s *MaildirStore) SieveScript(_ context.Context, mailbox string) (io.ReadCloser, error) {
	path, err := s.sieveScriptPath(mailbox)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}
