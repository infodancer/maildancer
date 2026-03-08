// Package grpcserver implements the mail-session gRPC services.
package grpcserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/infodancer/maildancer/internal/mail-session/deliver"
	"github.com/infodancer/maildancer/internal/mail-session/session"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// Server holds the gRPC server and the shared session state.
type Server struct {
	mu         sync.Mutex
	sess       *session.Session
	deliverer  *deliver.Deliverer // nil if delivery not configured
	grpcServer *grpc.Server

	// idleTimer tracks inactivity for automatic shutdown.
	idleTimer   *time.Timer
	idleTimeout time.Duration
	activeWatch int // number of active Watch streams

	// rescanInterval for periodic rescans (Watch service).
	rescanInterval time.Duration
}

// Config holds the configuration for the gRPC server.
type Config struct {
	// Session is the underlying mail session (required).
	Session *session.Session

	// Deliverer is the delivery pipeline (optional; nil disables DeliveryService).
	Deliverer *deliver.Deliverer

	// IdleTimeout is how long to wait with no activity before shutting down.
	// Zero means no idle timeout.
	IdleTimeout time.Duration

	// RescanInterval is how often to poll for new messages in Watch streams.
	// Zero means use 30s default.
	RescanInterval time.Duration
}

// NewServer creates a new gRPC server with all services registered.
func NewServer(cfg Config) *Server {
	srv := &Server{
		sess:           cfg.Session,
		deliverer:      cfg.Deliverer,
		rescanInterval: cfg.RescanInterval,
		idleTimeout:    cfg.IdleTimeout,
	}

	if srv.rescanInterval == 0 {
		srv.rescanInterval = 30 * time.Second
	}

	opts := []grpc.ServerOption{}
	if cfg.IdleTimeout > 0 {
		srv.idleTimer = time.AfterFunc(cfg.IdleTimeout, func() {
			srv.mu.Lock()
			active := srv.activeWatch
			srv.mu.Unlock()
			if active > 0 {
				// Reset timer if watches are active.
				srv.resetIdleTimer()
				return
			}
			slog.Info("idle timeout reached, shutting down")
			srv.grpcServer.GracefulStop()
		})
		// Wrap with unary and stream interceptors that reset the timer.
		opts = append(opts,
			grpc.UnaryInterceptor(srv.unaryIdleInterceptor),
			grpc.StreamInterceptor(srv.streamIdleInterceptor),
		)
	}

	srv.grpcServer = grpc.NewServer(opts...)

	// Register services.
	pb.RegisterMailboxServiceServer(srv.grpcServer, &MailboxServer{srv: srv})
	pb.RegisterFolderServiceServer(srv.grpcServer, &FolderServer{srv: srv})
	pb.RegisterWatchServiceServer(srv.grpcServer, &WatchServer{srv: srv})
	if srv.deliverer != nil {
		pb.RegisterDeliveryServiceServer(srv.grpcServer, &DeliveryServer{srv: srv})
	}

	return srv
}

// Serve starts listening on the given unix domain socket path.
// It sets socket permissions to 0600 and writes "READY\n" to stdout
// when the socket is ready to accept connections.
func (s *Server) Serve(socketPath string) error {
	// Remove stale socket.
	_ = os.Remove(socketPath)

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen %q: %w", socketPath, err)
	}

	// Restrict socket access to the owning user.
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = lis.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Signal readiness to the spawning process.
	fmt.Fprintln(os.Stdout, "READY")

	return s.grpcServer.Serve(lis)
}

// GracefulStop gracefully stops the server.
func (s *Server) GracefulStop() {
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.grpcServer.GracefulStop()
}

// resetIdleTimer resets the idle timer to the configured timeout.
func (s *Server) resetIdleTimer() {
	if s.idleTimer != nil {
		s.idleTimer.Reset(s.idleTimeout)
	}
}

// unaryIdleInterceptor resets the idle timer on each unary RPC.
func (s *Server) unaryIdleInterceptor(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	s.resetIdleTimer()
	return handler(ctx, req)
}

// streamIdleInterceptor resets the idle timer on each stream RPC.
func (s *Server) streamIdleInterceptor(
	srv any,
	ss grpc.ServerStream,
	_ *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	s.resetIdleTimer()
	return handler(srv, ss)
}
