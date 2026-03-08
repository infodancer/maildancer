package grpcserver

import (
	"io"

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
		Sender:            meta.GetSender(),
		Recipient:         meta.GetRecipient(),
		ClientIP:          meta.GetClientIp(),
		ClientHostname:    meta.GetClientHostname(),
		Forwarded:         meta.GetForwarded(),
		EncryptionKeyHint: meta.GetEncryptionKeyHint(),
		ReceivedTime:      meta.GetReceivedTime(),
	}

	resp, err := d.srv.deliverer.Deliver(stream.Context(), req, body)
	if err != nil {
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

	return stream.SendAndClose(pbResp)
}
