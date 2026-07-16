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
	"os/user"
	"strconv"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/certutil"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/session-manager/queue"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// Server is the session manager gRPC server.
type Server struct {
	mgr  *manager.Manager
	gsrv *grpc.Server
}

// New creates a new gRPC server with all services registered.
// If TLS config is provided and complete, the server uses mTLS.
func New(mgr *manager.Manager, cfg *config.Config, mc metrics.Collector) (*Server, error) {
	var opts []grpc.ServerOption

	// Enable mTLS if TLS config is fully specified.
	if cfg.TLS.CACert != "" && cfg.TLS.ServerCert != "" && cfg.TLS.ServerKey != "" {
		tlsCfg, err := certutil.ServerTLSConfig(cfg.TLS.CACert, cfg.TLS.ServerCert, cfg.TLS.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("configure mTLS: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		slog.Info("mTLS enabled")
	}

	gsrv := grpc.NewServer(opts...)

	s := &Server{
		mgr:  mgr,
		gsrv: gsrv,
	}

	smpb.RegisterSessionServiceServer(gsrv, &sessionServer{mgr: mgr})
	pb.RegisterMailboxServiceServer(gsrv, &mailboxProxy{mgr: mgr})
	pb.RegisterFolderServiceServer(gsrv, &folderProxy{mgr: mgr})
	pb.RegisterDeliveryServiceServer(gsrv, &deliveryProxy{mgr: mgr, metrics: mc})
	pb.RegisterWatchServiceServer(gsrv, &watchProxy{mgr: mgr})

	// Register OutboundService if queue is configured.
	if cfg.Queue.Dir != "" {
		queueCfg := queue.Config{
			Dir:        cfg.Queue.Dir,
			MessageTTL: cfg.Queue.GetMessageTTL(),
			Hostname:   cfg.Queue.Hostname,
		}
		pb.RegisterOutboundServiceServer(gsrv, &outboundServer{
			queueCfg:    queueCfg,
			domainsPath: cfg.DomainsPath,
			metrics:     mc,
		})
		slog.Info("outbound queue service enabled", "dir", cfg.Queue.Dir)
	}

	healthSrv := health.NewServer()
	healthgrpc.RegisterHealthServer(gsrv, healthSrv)
	healthSrv.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)

	return s, nil
}

// ServeUnix starts the gRPC server on a unix domain socket. socketGroup
// optionally names a group given connect access (see applySocketAccess);
// empty keeps the socket root-only.
func (s *Server) ServeUnix(socketPath, socketGroup string) error {
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}

	if err := applySocketAccess(socketPath, socketGroup); err != nil {
		_ = ln.Close()
		return err
	}

	slog.Info("listening (unix)", "socket", socketPath)
	_, _ = fmt.Fprintln(os.Stdout, "READY")

	return s.gsrv.Serve(ln)
}

// applySocketAccess sets ownership and permissions on the freshly created
// unix socket. With no group named, the socket is root-only (0600, the
// long-standing posture). With a group named and the process running as
// root, the socket becomes root:<gid> 0770 so the unprivileged protocol
// daemons in that group can connect. A failed group lookup or an off-root
// run logs a warning and keeps 0600 -- failing toward the tighter posture,
// never a more open one.
func applySocketAccess(socketPath, socketGroup string) error {
	mode := os.FileMode(0600)

	if socketGroup != "" {
		gid, err := resolveGID(socketGroup)
		switch {
		case err != nil:
			slog.Warn("socket_group lookup failed; socket stays root-only",
				"group", socketGroup, "error", err)
		case os.Geteuid() != 0:
			slog.Warn("not running as root; cannot chown socket, socket stays root-only",
				"group", socketGroup)
		default:
			if err := os.Chown(socketPath, 0, gid); err != nil {
				return fmt.Errorf("chown socket: %w", err)
			}
			mode = 0770
		}
	}

	if err := os.Chmod(socketPath, mode); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	return nil
}

// resolveGID looks up a group by name and returns its numeric gid.
func resolveGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q has non-numeric gid %q", name, g.Gid)
	}
	return gid, nil
}

// ServeTCP starts the gRPC server on a TCP address (requires mTLS).
func (s *Server) ServeTCP(address string) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}

	slog.Info("listening (tcp+mTLS)", "address", address)
	_, _ = fmt.Fprintln(os.Stdout, "READY")

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
