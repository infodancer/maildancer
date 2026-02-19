package imap

import (
	"context"

	"github.com/infodancer/maildancer/internal/imapd/server"
)

// Command represents an IMAP command that can be executed.
type Command interface {
	// Name returns the command name (e.g., "LOGIN", "SELECT").
	Name() string

	// Execute processes the command and writes responses to the connection.
	// The tag is the client-assigned command tag.
	// args is the raw argument string after the command name.
	Execute(ctx context.Context, tag string, args string, sess *Session, conn *server.Connection) error
}

// commandRegistry holds all registered commands.
var commandRegistry = map[string]Command{}

// RegisterCommand registers a command in the registry.
func RegisterCommand(cmd Command) {
	commandRegistry[cmd.Name()] = cmd
}

// GetCommand retrieves a command from the registry by name.
func GetCommand(name string) (Command, bool) {
	cmd, ok := commandRegistry[name]
	return cmd, ok
}

// flushConn flushes the connection writer.
func flushConn(conn *server.Connection) error {
	return conn.Flush()
}
