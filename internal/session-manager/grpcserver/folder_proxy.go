package grpcserver

import (
	"context"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type folderProxy struct {
	pb.UnimplementedFolderServiceServer
	mgr *manager.Manager
}

func (p *folderProxy) upstream(ctx context.Context) (pb.FolderServiceClient, error) {
	token, err := tokenFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	_, folders, _, err := p.mgr.SessionForToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return folders, nil
}

func (p *folderProxy) ListFolders(ctx context.Context, req *pb.ListFoldersRequest) (*pb.ListFoldersResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.ListFolders(ctx, req)
}

func (p *folderProxy) CreateFolder(ctx context.Context, req *pb.CreateFolderRequest) (*pb.CreateFolderResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.CreateFolder(ctx, req)
}

func (p *folderProxy) DeleteFolder(ctx context.Context, req *pb.DeleteFolderRequest) (*pb.DeleteFolderResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.DeleteFolder(ctx, req)
}

func (p *folderProxy) RenameFolder(ctx context.Context, req *pb.RenameFolderRequest) (*pb.RenameFolderResponse, error) {
	cl, err := p.upstream(ctx)
	if err != nil {
		return nil, err
	}
	return cl.RenameFolder(ctx, req)
}
