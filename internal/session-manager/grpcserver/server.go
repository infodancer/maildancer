// Package grpcserver implements the session manager gRPC server.
// It hosts SessionService (Login/Logout) and proxies MailboxService,
// FolderService, DeliveryService, and WatchService to per-user
// mail-session processes.
package grpcserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Server is the session manager gRPC server.
type Server struct {
	mgr  *manager.Manager
	gsrv *grpc.Server
}

// New creates a new gRPC server with all services registered.
func New(mgr *manager.Manager) *Server {
	gsrv := grpc.NewServer()

	s := &Server{
		mgr:  mgr,
		gsrv: gsrv,
	}

	smpb.RegisterSessionServiceServer(gsrv, &sessionServer{mgr: mgr})
	pb.RegisterMailboxServiceServer(gsrv, &mailboxProxy{mgr: mgr})
	pb.RegisterFolderServiceServer(gsrv, &folderProxy{mgr: mgr})
	pb.RegisterDeliveryServiceServer(gsrv, &deliveryProxy{mgr: mgr})
	pb.RegisterWatchServiceServer(gsrv, &watchProxy{mgr: mgr})

	return s
}

// Serve starts the gRPC server on the given unix socket path.
func (s *Server) Serve(socketPath string) error {
	// Remove stale socket if present.
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Restrict socket permissions to owner only.
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	slog.Info("session manager listening", "socket", socketPath)

	// Write READY signal to stdout so parent can detect startup.
	fmt.Fprintln(os.Stdout, "READY")

	return s.gsrv.Serve(ln)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	s.gsrv.GracefulStop()
}

// tokenFromContext extracts the session token from gRPC metadata.
func tokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("missing gRPC metadata")
	}
	tokens := md.Get("session-token")
	if len(tokens) == 0 || tokens[0] == "" {
		return "", fmt.Errorf("missing session-token in metadata")
	}
	return tokens[0], nil
}
