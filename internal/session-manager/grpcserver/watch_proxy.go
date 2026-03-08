package grpcserver

import (
	"io"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type watchProxy struct {
	pb.UnimplementedWatchServiceServer
	mgr *manager.Manager
}

func (p *watchProxy) Watch(req *pb.WatchRequest, stream pb.WatchService_WatchServer) error {
	token, err := tokenFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	_, _, watchCl, err := p.mgr.SessionForToken(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	upstream, err := watchCl.Watch(stream.Context(), req)
	if err != nil {
		return err
	}

	for {
		event, err := upstream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(event); err != nil {
			return err
		}
	}
}
