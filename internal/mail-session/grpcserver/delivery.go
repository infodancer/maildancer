package grpcserver

import (
	"io"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/infodancer/maildancer/internal/mail-session/deliver"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// DeliveryServer implements the DeliveryService gRPC service.
type DeliveryServer struct {
	pb.UnimplementedDeliveryServiceServer
	srv *Server
}

func (d *DeliveryServer) Deliver(stream pb.DeliveryService_DeliverServer) error {
	if d.srv.deliverer == nil {
		return status.Error(codes.Unavailable, "delivery service not configured")
	}

	// Read first message: must be metadata.
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "receive metadata: %v", err)
	}
	meta := first.GetMetadata()
	if meta == nil {
		return status.Error(codes.InvalidArgument, "first message must contain delivery metadata")
	}

	// Read body chunks.
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

	req := deliver.DeliverRequest{
		Sender:         meta.GetSender(),
		Recipient:      meta.GetRecipient(),
		ClientIP:       meta.GetClientIp(),
		ClientHostname: meta.GetClientHostname(),
		Forwarded:      meta.GetForwarded(),
		ReceivedTime:   meta.GetReceivedTime(),
		MsgID:          meta.GetMsgid(),
	}

	resp, err := d.srv.deliverer.Deliver(stream.Context(), req, body)
	if err != nil {
		// Pipeline error (not a clean reject): log it here -- the caller only
		// sees a gRPC status -- so the failure is traceable by msgid.
		slog.Error("delivery pipeline failed",
			slog.String("msgid", req.MsgID),
			slog.String("recipient", req.Recipient),
			slog.String("error", err.Error()))
		return status.Errorf(codes.Internal, "delivery failed: %v", err)
	}

	pbResp := &pb.DeliverResponse{
		Temporary:         resp.Temporary,
		Reason:            resp.Reason,
		RedirectAddresses: resp.RedirectAddresses,
	}
	switch resp.Result {
	case deliver.ResultDelivered:
		pbResp.Result = pb.DeliverResult_DELIVER_RESULT_DELIVERED
	case deliver.ResultRejected:
		pbResp.Result = pb.DeliverResult_DELIVER_RESULT_REJECTED
	case deliver.ResultRedirected:
		pbResp.Result = pb.DeliverResult_DELIVER_RESULT_REDIRECTED
	}

	// One authoritative result line per delivery, keyed by msgid, regardless of
	// which pipeline path (keep, fileinto, redirect, reject) produced it.
	attrs := []any{
		slog.String("msgid", req.MsgID),
		slog.String("recipient", req.Recipient),
		slog.String("result", resp.Result.String()),
	}
	if resp.Result == deliver.ResultRejected {
		attrs = append(attrs, slog.Bool("temporary", resp.Temporary), slog.String("reason", resp.Reason))
	}
	if resp.Result == deliver.ResultRedirected {
		attrs = append(attrs, slog.Int("redirects", len(resp.RedirectAddresses)))
	}
	slog.Info("delivery result", attrs...)

	return stream.SendAndClose(pbResp)
}
