package grpcserver

import (
	"context"
	"io"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mailboxProxy struct {
	pb.UnimplementedMailboxServiceServer
	mgr *manager.Manager
}

func (p *mailboxProxy) upstream(ctx context.Context) (pb.MailboxServiceClient, error) {
	token, err := tokenFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	mailbox, _, _, err := p.mgr.SessionForToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return mailbox, nil
}

func (p *mailboxProxy) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.List(ctx, req)
}

func (p *mailboxProxy) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Stat(ctx, req)
}

func (p *mailboxProxy) Fetch(req *pb.FetchRequest, stream pb.MailboxService_FetchServer) error {
	cl, err := p.upstream(stream.Context())
	if err != nil {
		return err
	}
	upstream, err := cl.Fetch(stream.Context(), req)
	if err != nil {
		return err
	}
	for {
		resp, err := upstream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (p *mailboxProxy) FetchHeaders(ctx context.Context, req *pb.FetchHeadersRequest) (*pb.FetchHeadersResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.FetchHeaders(ctx, req)
}

func (p *mailboxProxy) SearchContent(ctx context.Context, req *pb.SearchContentRequest) (*pb.SearchContentResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.SearchContent(ctx, req)
}

func (p *mailboxProxy) Append(stream pb.MailboxService_AppendServer) error {
	cl, err := p.upstream(stream.Context())
	if err != nil {
		return err
	}
	upstream, err := cl.Append(stream.Context())
	if err != nil {
		return err
	}
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			resp, err := upstream.CloseAndRecv()
			if err != nil {
				return err
			}
			return stream.SendAndClose(resp)
		}
		if err != nil {
			return err
		}
		if err := upstream.Send(req); err != nil {
			return err
		}
	}
}

func (p *mailboxProxy) Copy(ctx context.Context, req *pb.CopyRequest) (*pb.CopyResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Copy(ctx, req)
}

func (p *mailboxProxy) Move(ctx context.Context, req *pb.MoveRequest) (*pb.MoveResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Move(ctx, req)
}

func (p *mailboxProxy) SetFlags(ctx context.Context, req *pb.SetFlagsRequest) (*pb.SetFlagsResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.SetFlags(ctx, req)
}

func (p *mailboxProxy) Expunge(ctx context.Context, req *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Expunge(ctx, req)
}

func (p *mailboxProxy) Rescan(ctx context.Context, req *pb.RescanRequest) (*pb.RescanResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Rescan(ctx, req)
}

func (p *mailboxProxy) UIDValidity(ctx context.Context, req *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.UIDValidity(ctx, req)
}

func (p *mailboxProxy) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Delete(ctx, req)
}

func (p *mailboxProxy) Undelete(ctx context.Context, req *pb.UndeleteRequest) (*pb.UndeleteResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Undelete(ctx, req)
}

func (p *mailboxProxy) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Commit(ctx, req)
}
