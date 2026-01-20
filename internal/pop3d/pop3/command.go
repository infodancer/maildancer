package pop3

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// ConnectionLogger is the interface for accessing logger from commands.
type ConnectionLogger interface {
	Logger() *slog.Logger
}

// Command represents a POP3 command that can be executed.
type Command interface {
	// Name returns the command name (e.g., "USER", "PASS", "QUIT").
	Name() string

	// Execute processes the command and returns a response.
	// The response should not include the +OK or -ERR prefix.
	// conn provides access to the connection logger.
	Execute(ctx context.Context, sess *Session, conn ConnectionLogger, args []string) (Response, error)
}

// Response represents a POP3 response to a command.
type Response struct {
	// OK indicates success (+OK) or failure (-ERR).
	OK bool

	// Message is the response message (without +OK/-ERR prefix).
	Message string

	// Lines contains multi-line response data (for commands like CAPA).
	// If present, will be sent after the +OK message, terminated by ".".
	Lines []string

	// Continuation indicates this is a SASL continuation response.
	// If true, the response is formatted as "+ <Challenge>" instead of +OK/-ERR.
	Continuation bool

	// Challenge is the base64-encoded SASL challenge data.
	// Only used when Continuation is true.
	Challenge string
}

// String formats the response as a POP3 protocol string.
func (r Response) String() string {
	var sb strings.Builder

	// Handle SASL continuation response
	if r.Continuation {
		sb.WriteString("+ ")
		sb.WriteString(r.Challenge)
		sb.WriteString("\r\n")
		return sb.String()
	}

	if r.OK {
		sb.WriteString("+OK")
	} else {
		sb.WriteString("-ERR")
	}

	if r.Message != "" {
		sb.WriteString(" ")
		sb.WriteString(r.Message)
	}

	sb.WriteString("\r\n")

	// Add multi-line data if present
	if len(r.Lines) > 0 {
		for _, line := range r.Lines {
			// Byte-stuff lines that start with "."
			if strings.HasPrefix(line, ".") {
				sb.WriteString(".")
			}
			sb.WriteString(line)
			sb.WriteString("\r\n")
		}
		sb.WriteString(".\r\n")
	}

	return sb.String()
}

// commandRegistry holds all registered commands.
var commandRegistry = make(map[string]Command)

// RegisterCommand registers a command in the registry.
func RegisterCommand(cmd Command) {
	commandRegistry[strings.ToUpper(cmd.Name())] = cmd
}

// GetCommand retrieves a command from the registry by name.
func GetCommand(name string) (Command, bool) {
	cmd, ok := commandRegistry[strings.ToUpper(name)]
	return cmd, ok
}

// ParseCommand parses a POP3 command line into command name and arguments.
// Returns the command name and arguments, or an error if the line is invalid.
func ParseCommand(line string) (string, []string, error) {
	// Trim whitespace
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil, fmt.Errorf("empty command")
	}

	// Split on whitespace
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty command")
	}

	cmdName := strings.ToUpper(parts[0])
	args := parts[1:]

	return cmdName, args, nil
}
