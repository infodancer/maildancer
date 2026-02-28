// Package protocol implements the session pipe protocol parser and response writer.
package protocol

// Command names understood by the protocol loop.
const (
	CmdMailbox  = "MAILBOX"
	CmdList     = "LIST"
	CmdStat     = "STAT"
	CmdGet      = "GET"
	CmdHeaders  = "HEADERS"
	CmdDelete   = "DELETE"
	CmdUndelete = "UNDELETE"
	CmdCommit   = "COMMIT"
	CmdQuit     = "QUIT"
)

// Command holds a parsed command from the client.
type Command struct {
	// Name is the uppercased command keyword (e.g. "LIST", "GET").
	Name string

	// Args contains the whitespace-separated arguments following the command name.
	Args []string
}
