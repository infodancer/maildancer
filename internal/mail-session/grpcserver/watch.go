package grpcserver

import (
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// WatchServer implements the WatchService gRPC service.
type WatchServer struct {
	pb.UnimplementedWatchServiceServer
	srv *Server
}

func (w *WatchServer) Watch(req *pb.WatchRequest, stream pb.WatchService_WatchServer) error {
	folder := req.GetFolder()
	if folder == "" {
		folder = "INBOX"
	}

	// Track active watch for idle reaping.
	w.srv.mu.Lock()
	w.srv.activeWatch++
	w.srv.mu.Unlock()
	defer func() {
		w.srv.mu.Lock()
		w.srv.activeWatch--
		w.srv.mu.Unlock()
	}()

	// Initial select to populate the cache.
	w.srv.mu.Lock()
	if _, err := w.srv.sess.Select(stream.Context(), folder); err != nil {
		w.srv.mu.Unlock()
		return status.Errorf(codes.Internal, "select %q: %v", folder, err)
	}
	w.srv.mu.Unlock()

	ticker := time.NewTicker(w.srv.rescanInterval)
	defer ticker.Stop()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.srv.mu.Lock()
			// Re-select the folder to ensure we're looking at the right one.
			if _, err := w.srv.sess.Select(ctx, folder); err != nil {
				w.srv.mu.Unlock()
				slog.Warn("watch rescan select failed", "folder", folder, "error", err)
				continue
			}
			newMsgs, err := w.srv.sess.Rescan(ctx)
			w.srv.mu.Unlock()

			if err != nil {
				slog.Warn("watch rescan failed", "folder", folder, "error", err)
				continue
			}

			if len(newMsgs) > 0 {
				pbMsgs := make([]*pb.MessageInfo, 0, len(newMsgs))
				for _, msg := range newMsgs {
					pbMsgs = append(pbMsgs, &pb.MessageInfo{
						Uid:   msg.UID,
						Size:  msg.Size,
						Flags: msg.Flags,
					})
				}
				event := &pb.WatchEvent{
					Event: &pb.WatchEvent_NewMessages{
						NewMessages: &pb.NewMessagesEvent{
							Messages: pbMsgs,
						},
					},
				}
				if err := stream.Send(event); err != nil {
					return err
				}
			}
		}
	}
}
