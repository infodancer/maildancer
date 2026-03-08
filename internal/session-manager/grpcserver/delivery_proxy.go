package grpcserver

import (
	"fmt"
	"io"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
)

type deliveryProxy struct {
	pb.UnimplementedDeliveryServiceServer
	mgr *manager.Manager
}

// Deliver proxies a delivery request by spawning a oneshot mail-session for
// the recipient. The recipient is extracted from the first DeliverRequest
// metadata chunk.
func (p *deliveryProxy) Deliver(stream pb.DeliveryService_DeliverServer) error {
	// Read the first chunk to get the metadata with the recipient.
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv metadata: %w", err)
	}
	meta := first.GetMetadata()
	if meta == nil {
		return fmt.Errorf("first chunk must contain delivery metadata")
	}

	// Spawn oneshot mail-session for this recipient.
	deliveryCl, cleanup, err := p.mgr.DeliverySession(stream.Context(), meta.Recipient)
	if err != nil {
		return err
	}
	defer cleanup()

	// Open upstream delivery stream.
	upstream, err := deliveryCl.Deliver(stream.Context())
	if err != nil {
		return err
	}

	// Forward the first chunk (metadata).
	if err := upstream.Send(first); err != nil {
		return err
	}

	// Forward remaining body chunks.
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
