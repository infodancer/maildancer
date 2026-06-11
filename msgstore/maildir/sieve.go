package maildir

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	gosieve "git.sr.ht/~emersion/go-sieve"
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

// loadSieveScript loads and parses the Sieve script for a mailbox.
//
// Returns (nil, nil) if no script exists -- delivery continues normally.
// Returns (nil, err) if the script exists but fails to parse -- the error
// is logged and delivery falls through to default behavior (fail-safe).
func (s *MaildirStore) loadSieveScript(mailbox string) ([]gosieve.Command, error) {
	path, err := s.sieveScriptPath(mailbox)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	cmds, err := gosieve.Parse(f)
	if err != nil {
		return nil, err
	}

	slog.Debug("loaded sieve script", slog.String("mailbox", mailbox), slog.Int("commands", len(cmds)))
	return cmds, nil
}
