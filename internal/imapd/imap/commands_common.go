package imap

import (
	"context"
	"strings"

	"github.com/infodancer/maildancer/internal/imapd/server"
)

// capabilityCommand implements the CAPABILITY command.
type capabilityCommand struct{}

func (c *capabilityCommand) Name() string { return "CAPABILITY" }

func (c *capabilityCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	caps := sess.Capabilities(conn.IsTLS())
	w := conn.Writer()
	if err := writeUntagged(w, "CAPABILITY "+strings.Join(caps, " ")); err != nil {
		return err
	}
	return writeOK(w, tag, "CAPABILITY completed")
}

// noopCommand implements the NOOP command.
type noopCommand struct{}

func (c *noopCommand) Name() string { return "NOOP" }

func (c *noopCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	return writeOK(conn.Writer(), tag, "NOOP completed")
}

// logoutCommand implements the LOGOUT command.
type logoutCommand struct{}

func (c *logoutCommand) Name() string { return "LOGOUT" }

func (c *logoutCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	w := conn.Writer()
	if err := writeUntagged(w, "BYE IMAP4rev1 server logging out"); err != nil {
		return err
	}
	sess.SetLogout()
	return writeOK(w, tag, "LOGOUT completed")
}

// checkCommand implements the CHECK command.
type checkCommand struct{}

func (c *checkCommand) Name() string { return "CHECK" }

func (c *checkCommand) Execute(ctx context.Context, tag, args string, sess *Session, conn *server.Connection) error {
	if sess.State() != StateSelected {
		return writeBAD(conn.Writer(), tag, "CHECK requires selected state")
	}
	return writeOK(conn.Writer(), tag, "CHECK completed")
}
