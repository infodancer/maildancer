package grpcserver

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
)

type deliveryProxy struct {
	pb.UnimplementedDeliveryServiceServer
	mgr     *manager.Manager
	metrics metrics.Collector
}

// Deliver proxies a delivery request by spawning a oneshot mail-session for
// the recipient. The recipient is extracted from the first DeliverRequest
// metadata chunk.
//
// Unlike the other proxied RPCs, Deliver does not require a session token.
// Authentication is implicit: unix socket mode uses 0600 perms restricting
// access to the session-manager user; mTLS mode requires a valid client cert.
// Only smtpd calls this RPC.
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

	slog.Info("delivery request",
		"msgid", meta.GetMsgid(),
		"to", meta.Recipient,
		"from", meta.Sender)

	recipientDomain := "unknown"
	if _, d, ok := strings.Cut(meta.Recipient, "@"); ok {
		recipientDomain = d
	}

	// Resolve forwarding here, as root, before the credential lookup and
	// privilege drop. This is the single forwarding decision point: a forward
	// must be able to re-send (only smtpd can), and the admin/domain tiers live
	// in the config tree that the privilege-dropped mail-session cannot read.
	// Resolving before DeliverySession also means forward-only addresses (no
	// mailbox, hence no uid) are redirected instead of failing credential lookup.
	//
	// meta.Forwarded marks a re-submitted forward (smtpd's followRedirect): do
	// not resolve again, enforcing the 1-hop ceiling.
	if !meta.GetForwarded() {
		if targets, ok := p.mgr.ResolveForward(stream.Context(), meta.Recipient); ok {
			return p.respondForward(stream, meta, recipientDomain, targets)
		}
	}

	// Spawn oneshot mail-session for this recipient.
	deliveryCl, cleanup, err := p.mgr.DeliverySession(stream.Context(), meta.Recipient)
	if err != nil {
		slog.Warn("delivery session failed",
			"msgid", meta.GetMsgid(),
			"to", meta.Recipient,
			"error", err)
		p.metrics.DeliveryProxyCompleted(recipientDomain, "error")
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
				slog.Warn("delivery failed",
					"msgid", meta.GetMsgid(),
					"to", meta.Recipient,
					"from", meta.Sender,
					"error", err)
				p.metrics.DeliveryProxyCompleted(recipientDomain, "error")
				return err
			}
			slog.Info("delivery complete",
				"msgid", meta.GetMsgid(),
				"to", meta.Recipient,
				"from", meta.Sender)
			p.metrics.DeliveryProxyCompleted(recipientDomain, "success")
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

// respondForward answers a delivery that resolved to a forward, without
// spawning a mail-session. smtpd's followRedirect performs the actual re-send;
// here we only return the verdict. The inbound body stream is drained and
// discarded first so the client's CloseAndRecv completes cleanly -- the forward
// decision is recipient-based and never needs the body.
//
// Forwarding is strictly 1:1. A multi-target rule is a configuration error;
// like the former mail-session path, we temp-fail (the sending MTA holds and
// retries while the admin corrects it) rather than fan out.
func (p *deliveryProxy) respondForward(stream pb.DeliveryService_DeliverServer, meta *pb.DeliverMetadata, recipientDomain string, targets []string) error {
	if err := drainDeliverStream(stream); err != nil {
		return err
	}

	if len(targets) > 1 {
		slog.Error("forwarding misconfiguration: multiple forward targets configured (1:1 required)",
			"msgid", meta.GetMsgid(),
			"to", meta.Recipient,
			"target_count", len(targets))
		p.metrics.DeliveryProxyCompleted(recipientDomain, "error")
		return stream.SendAndClose(&pb.DeliverResponse{
			Result:    pb.DeliverResult_DELIVER_RESULT_REJECTED,
			Temporary: true,
			Reason:    fmt.Sprintf("forwarding misconfiguration: only one forward destination allowed, %d configured", len(targets)),
		})
	}

	slog.Info("delivery forwarded",
		"msgid", meta.GetMsgid(),
		"to", meta.Recipient,
		"target", targets[0])
	p.metrics.DeliveryProxyCompleted(recipientDomain, "forwarded")
	return stream.SendAndClose(&pb.DeliverResponse{
		Result:            pb.DeliverResult_DELIVER_RESULT_REDIRECTED,
		RedirectAddresses: targets,
	})
}

// drainDeliverStream reads and discards remaining inbound chunks until EOF.
func drainDeliverStream(stream pb.DeliveryService_DeliverServer) error {
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
