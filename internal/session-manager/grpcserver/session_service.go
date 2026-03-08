package grpcserver

import (
	"context"
	"log/slog"

	"github.com/infodancer/maildancer/internal/session-manager/manager"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sessionServer struct {
	smpb.UnimplementedSessionServiceServer
	mgr *manager.Manager
}

func (s *sessionServer) Login(ctx context.Context, req *smpb.LoginRequest) (*smpb.LoginResponse, error) {
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password required")
	}

	token, mailbox, err := s.mgr.Login(ctx, req.Username, req.Password)
	if err != nil {
		slog.Warn("login failed", "username", req.Username, "error", err)
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
	}

	return &smpb.LoginResponse{
		SessionToken: token,
		Mailbox:      mailbox,
	}, nil
}

func (s *sessionServer) Logout(ctx context.Context, req *smpb.LogoutRequest) (*smpb.LogoutResponse, error) {
	if req.SessionToken == "" {
		return nil, status.Error(codes.InvalidArgument, "session_token required")
	}

	if err := s.mgr.Logout(ctx, req.SessionToken); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	return &smpb.LogoutResponse{}, nil
}
