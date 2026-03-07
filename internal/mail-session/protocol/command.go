// Package protocol implements the session pipe protocol parser and response writer.
package protocol

// Command names understood by the protocol loop.
const (
	// POP3-path commands (unchanged).
	CmdMailbox  = "MAILBOX"
	CmdList     = "LIST"
	CmdStat     = "STAT"
	CmdGet      = "GET"
	CmdHeaders  = "HEADERS"
	CmdDelete   = "DELETE"
	CmdUndelete = "UNDELETE"
	CmdCommit   = "COMMIT"
	CmdQuit     = "QUIT"

	// IMAP-path commands.
	CmdSelect       = "SELECT"       // SELECT <folder> — select folder, return message list
	CmdFolders      = "FOLDERS"      // FOLDERS — list all non-INBOX folders
	CmdUIDValidity  = "UIDVALIDITY"  // UIDVALIDITY <folder> — return UIDValidity uint32
	CmdCreateFolder = "CREATEFOLDER" // CREATEFOLDER <name>
	CmdDeleteFolder = "DELETEFOLDER" // DELETEFOLDER <name>
	CmdRenameFolder = "RENAMEFOLDER" // RENAMEFOLDER <old> <new>
	CmdSetFlags     = "SETFLAGS"     // SETFLAGS <uid> <flag1>[,flag2,...] — replace flag set
	CmdExpunge      = "EXPUNGE"      // EXPUNGE — flush \Deleted messages, return expelled UIDs
	CmdAppend       = "APPEND"       // APPEND <folder> <size> <flags-csv-or-NONE> <date-rfc3339>
	CmdCopy         = "COPY"         // COPY <uid> <dest-folder> — copy message, return dest UID
	CmdMove         = "MOVE"         // MOVE <uid> <src-folder> <dest-folder> — atomic move, return dest UID
	CmdRescan       = "RESCAN"       // RESCAN — re-read current folder, return new messages only
)

// Command holds a parsed command from the client.
type Command struct {
	// Name is the uppercased command keyword (e.g. "LIST", "GET").
	Name string

	// Args contains the whitespace-separated arguments following the command name.
	Args []string
}
