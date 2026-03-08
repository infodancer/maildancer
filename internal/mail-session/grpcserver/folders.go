package grpcserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// FolderServer implements the FolderService gRPC service.
type FolderServer struct {
	pb.UnimplementedFolderServiceServer
	srv *Server
}

func (f *FolderServer) ListFolders(ctx context.Context, _ *pb.ListFoldersRequest) (*pb.ListFoldersResponse, error) {
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()

	folders, err := f.srv.sess.Folders(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list folders: %v", err)
	}
	return &pb.ListFoldersResponse{Folders: folders}, nil
}

func (f *FolderServer) CreateFolder(ctx context.Context, req *pb.CreateFolderRequest) (*pb.CreateFolderResponse, error) {
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()

	if err := f.srv.sess.CreateFolder(ctx, req.GetName()); err != nil {
		return nil, status.Errorf(codes.Internal, "create folder: %v", err)
	}
	return &pb.CreateFolderResponse{}, nil
}

func (f *FolderServer) DeleteFolder(ctx context.Context, req *pb.DeleteFolderRequest) (*pb.DeleteFolderResponse, error) {
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()

	if err := f.srv.sess.DeleteFolder(ctx, req.GetName()); err != nil {
		return nil, status.Errorf(codes.Internal, "delete folder: %v", err)
	}
	return &pb.DeleteFolderResponse{}, nil
}

func (f *FolderServer) RenameFolder(ctx context.Context, req *pb.RenameFolderRequest) (*pb.RenameFolderResponse, error) {
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()

	if err := f.srv.sess.RenameFolder(ctx, req.GetOldName(), req.GetNewName()); err != nil {
		return nil, status.Errorf(codes.Internal, "rename folder: %v", err)
	}
	return &pb.RenameFolderResponse{}, nil
}
