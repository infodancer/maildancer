package grpcserver

import (
	"context"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// MailboxServer implements the MailboxService gRPC service.
type MailboxServer struct {
	pb.UnimplementedMailboxServiceServer
	srv *Server
}

func (m *MailboxServer) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	msgs, err := m.srv.sess.Select(ctx, folder)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	pbMsgs := make([]*pb.MessageInfo, 0, len(msgs))
	for _, msg := range msgs {
		pbMsgs = append(pbMsgs, &pb.MessageInfo{
			Uid:   msg.UID,
			Size:  msg.Size,
			Flags: msg.Flags,
		})
	}
	return &pb.ListResponse{Messages: pbMsgs}, nil
}

func (m *MailboxServer) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	count, totalBytes := m.srv.sess.Stat()
	return &pb.StatResponse{
		Count:      int32(count),
		TotalBytes: totalBytes,
	}, nil
}

func (m *MailboxServer) Fetch(req *pb.FetchRequest, stream pb.MailboxService_FetchServer) error {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	ctx := stream.Context()
	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	rc, err := m.srv.sess.Retrieve(ctx, req.GetUid())
	if err != nil {
		return status.Errorf(codes.NotFound, "retrieve %q: %v", req.GetUid(), err)
	}
	defer func() { _ = rc.Close() }()

	buf := make([]byte, 64*1024)
	for {
		n, readErr := rc.Read(buf)
		if n > 0 {
			if sendErr := stream.Send(&pb.FetchResponse{Data: buf[:n]}); sendErr != nil {
				return sendErr
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return status.Errorf(codes.Internal, "read message: %v", readErr)
		}
	}
}

func (m *MailboxServer) FetchHeaders(ctx context.Context, req *pb.FetchHeadersRequest) (*pb.FetchHeadersResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	rc, err := m.srv.sess.Retrieve(ctx, req.GetUid())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "retrieve %q: %v", req.GetUid(), err)
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read message: %v", err)
	}

	headers := extractHeaders(data, int(req.GetBodyLines()))
	return &pb.FetchHeadersResponse{Headers: headers}, nil
}

func (m *MailboxServer) Append(stream pb.MailboxService_AppendServer) error {
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "receive metadata: %v", err)
	}
	meta := first.GetMetadata()
	if meta == nil {
		return status.Error(codes.InvalidArgument, "first message must contain metadata")
	}

	var body []byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "receive body chunk: %v", err)
		}
		body = append(body, chunk.GetData()...)
	}

	date, err := time.Parse(time.RFC3339, meta.GetDate())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid date: %v", err)
	}

	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	uid, err := m.srv.sess.AppendMessage(stream.Context(), meta.GetFolder(), body, meta.GetFlags(), date)
	if err != nil {
		return status.Errorf(codes.Internal, "append: %v", err)
	}

	return stream.SendAndClose(&pb.AppendResponse{Uid: uid})
}

func (m *MailboxServer) Copy(ctx context.Context, req *pb.CopyRequest) (*pb.CopyResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	newUID, err := m.srv.sess.CopyMessage(ctx, req.GetUid(), req.GetDestFolder())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "copy: %v", err)
	}
	return &pb.CopyResponse{NewUid: newUID}, nil
}

func (m *MailboxServer) Move(ctx context.Context, req *pb.MoveRequest) (*pb.MoveResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	newUID, err := m.srv.sess.MoveMessage(ctx, req.GetUid(), req.GetSrcFolder(), req.GetDestFolder())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "move: %v", err)
	}
	return &pb.MoveResponse{NewUid: newUID}, nil
}

func (m *MailboxServer) SetFlags(ctx context.Context, req *pb.SetFlagsRequest) (*pb.SetFlagsResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	if err := m.srv.sess.SetFlags(ctx, req.GetUid(), req.GetFlags()); err != nil {
		return nil, status.Errorf(codes.Internal, "set flags: %v", err)
	}
	return &pb.SetFlagsResponse{}, nil
}

func (m *MailboxServer) Expunge(ctx context.Context, req *pb.ExpungeRequest) (*pb.ExpungeResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	expelled, err := m.srv.sess.Expunge(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "expunge: %v", err)
	}
	return &pb.ExpungeResponse{ExpelledUids: expelled}, nil
}

func (m *MailboxServer) Rescan(ctx context.Context, req *pb.RescanRequest) (*pb.RescanResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	if _, err := m.srv.sess.Select(ctx, folder); err != nil {
		return nil, status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}

	newMsgs, err := m.srv.sess.Rescan(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "rescan: %v", err)
	}

	pbMsgs := make([]*pb.MessageInfo, 0, len(newMsgs))
	for _, msg := range newMsgs {
		pbMsgs = append(pbMsgs, &pb.MessageInfo{
			Uid:   msg.UID,
			Size:  msg.Size,
			Flags: msg.Flags,
		})
	}
	return &pb.RescanResponse{NewMessages: pbMsgs}, nil
}

func (m *MailboxServer) UIDValidity(ctx context.Context, req *pb.UIDValidityRequest) (*pb.UIDValidityResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	v, err := m.srv.sess.UIDValidity(ctx, req.GetFolder())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "uid validity: %v", err)
	}
	return &pb.UIDValidityResponse{UidValidity: v}, nil
}

func (m *MailboxServer) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	if err := m.srv.sess.Delete(req.GetUid()); err != nil {
		return nil, status.Errorf(codes.NotFound, "delete: %v", err)
	}
	return &pb.DeleteResponse{}, nil
}

func (m *MailboxServer) Undelete(ctx context.Context, req *pb.UndeleteRequest) (*pb.UndeleteResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	if err := m.srv.sess.Undelete(req.GetUid()); err != nil {
		return nil, status.Errorf(codes.NotFound, "undelete: %v", err)
	}
	return &pb.UndeleteResponse{}, nil
}

func (m *MailboxServer) Commit(ctx context.Context, _ *pb.CommitRequest) (*pb.CommitResponse, error) {
	m.srv.mu.Lock()
	defer m.srv.mu.Unlock()

	if err := m.srv.sess.Commit(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "commit: %v", err)
	}
	return &pb.CommitResponse{}, nil
}

// extractHeaders returns the header section of a message plus up to nLines of body.
func extractHeaders(data []byte, nLines int) []byte {
	s := string(data)
	inBody := false
	bodyCount := 0
	var out strings.Builder

	for len(s) > 0 {
		line := s
		idx := strings.Index(s, "\n")
		if idx >= 0 {
			line = s[:idx+1]
			s = s[idx+1:]
		} else {
			s = ""
		}

		if !inBody {
			out.WriteString(line)
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				inBody = true
			}
		} else {
			if nLines == 0 {
				break
			}
			out.WriteString(line)
			bodyCount++
			if bodyCount >= nLines {
				break
			}
		}
	}
	return []byte(out.String())
}
