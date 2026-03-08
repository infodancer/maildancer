package backend

import (
	"context"
	"os"
	"os/exec"
	"syscall"

	"github.com/infodancer/maildancer/internal/mail-session/client"
	"github.com/infodancer/maildancer/msgstore"
)

// rescanner is satisfied by stores that support incremental rescan (IDLE).
// Both SubprocessStore (pipe) and grpcStore (gRPC) implement this.
type rescanner interface {
	Rescan() ([]msgstore.MessageInfo, error)
}

// grpcStore wraps a mail-session gRPC client with subprocess lifecycle management.
// It embeds *client.Client, promoting all MessageStore, FolderStore, and mover
// methods. Close() handles gRPC disconnect, process termination, and socket cleanup.
type grpcStore struct {
	*client.Client
	cmd            *exec.Cmd
	socketDir      string
	selectedFolder string // tracks folder for Rescan; set by ListInFolder
}

// Close disconnects the gRPC client, terminates the mail-session subprocess,
// and removes the temporary socket directory.
func (g *grpcStore) Close() error {
	if g.Client != nil {
		_ = g.Client.Close()
	}
	if g.cmd != nil && g.cmd.Process != nil {
		_ = g.cmd.Process.Signal(syscall.SIGTERM)
		_ = g.cmd.Wait()
	}
	if g.socketDir != "" {
		_ = os.RemoveAll(g.socketDir)
	}
	return nil
}

// ListInFolder overrides the embedded client method to track the selected folder.
func (g *grpcStore) ListInFolder(ctx context.Context, mailbox string, folder string) ([]msgstore.MessageInfo, error) {
	g.selectedFolder = folder
	return g.Client.ListInFolder(ctx, mailbox, folder)
}

// Rescan re-reads the currently selected folder and returns only new messages.
// Satisfies the rescanner interface used by IDLE.
func (g *grpcStore) Rescan() ([]msgstore.MessageInfo, error) {
	folder := g.selectedFolder
	if folder == "" {
		folder = "INBOX"
	}
	return g.Client.Rescan(context.Background(), folder)
}

// Compile-time interface checks.
var (
	_ msgstore.MessageStore = (*grpcStore)(nil)
	_ msgstore.FolderStore  = (*grpcStore)(nil)
	_ mover                 = (*grpcStore)(nil)
	_ rescanner             = (*grpcStore)(nil)
)
