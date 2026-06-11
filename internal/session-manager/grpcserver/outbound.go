package grpcserver

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	dkimloader "github.com/infodancer/maildancer/internal/session-manager/dkim"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
	"github.com/infodancer/maildancer/internal/session-manager/queue"
)

type outboundServer struct {
	pb.UnimplementedOutboundServiceServer
	queueCfg    queue.Config
	domainsPath string
	metrics     metrics.Collector
}

// Enqueue accepts an outbound message via client-streaming (metadata + body
// chunks), DKIM-signs it if a key exists for the sender domain, and writes
// it to the mail queue.
//
// No session token is required -- access is controlled by socket perms / mTLS.
func (s *outboundServer) Enqueue(stream pb.OutboundService_EnqueueServer) error {
	// Read first chunk: must be metadata.
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv metadata: %w", err)
	}
	meta := first.GetMetadata()
	if meta == nil {
		return fmt.Errorf("first chunk must contain envelope metadata")
	}
	if meta.Sender == "" {
		return fmt.Errorf("sender is required")
	}
	if len(meta.Recipients) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}

	// Buffer remaining body chunks.
	var body bytes.Buffer
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("recv body: %w", err)
		}
		data := req.GetData()
		if data == nil {
			return fmt.Errorf("expected body data chunk, got metadata")
		}
		if _, err := body.Write(data); err != nil {
			return fmt.Errorf("buffer body: %w", err)
		}
	}

	bodySize := body.Len()

	// Configure DKIM signing for this sender domain.
	cfg := s.queueCfg
	senderDomain := extractSenderDomain(meta.Sender)
	selector, key, err := dkimloader.LoadDKIMKey(s.domainsPath, senderDomain)
	if err != nil {
		slog.Warn("DKIM key load failed, sending unsigned",
			"domain", senderDomain, "error", err)
		s.metrics.DKIMSignCompleted(senderDomain, "error")
	}
	if key != nil {
		cfg.DKIMSign = func(domain string, msg io.Reader) (io.Reader, error) {
			return queue.SignDKIM(domain, selector, key, msg)
		}
		slog.Info("DKIM signing enabled",
			"domain", senderDomain,
			"selector", selector,
			"from", meta.Sender)
		s.metrics.DKIMSignCompleted(senderDomain, "signed")
	} else if err == nil {
		slog.Debug("no DKIM key configured",
			"domain", senderDomain)
		s.metrics.DKIMSignCompleted(senderDomain, "skipped")
	}

	// Write to queue.
	msgID, err := queue.Write(cfg, meta.Sender, meta.Recipients, &body)
	if err != nil {
		slog.Warn("queue write failed",
			"from", meta.Sender,
			"to", meta.Recipients,
			"error", err)
		s.metrics.EnqueueCompleted(senderDomain, "error")
		return fmt.Errorf("queue write: %w", err)
	}

	s.metrics.EnqueueCompleted(senderDomain, "success")
	s.metrics.EnqueueSize(senderDomain, int64(bodySize))

	slog.Info("message enqueued",
		"msg_id", msgID,
		"from", meta.Sender,
		"to", meta.Recipients,
		"size", bodySize)

	return stream.SendAndClose(&pb.EnqueueResponse{
		MessageId: msgID,
	})
}

// extractSenderDomain returns the domain part of a sender address.
func extractSenderDomain(addr string) string {
	// Reuse the queue package's logic.
	_, domain := splitSenderAddress(addr)
	return domain
}

func splitSenderAddress(addr string) (string, string) {
	for len(addr) > 0 && addr[0] == '<' {
		addr = addr[1:]
	}
	for len(addr) > 0 && addr[len(addr)-1] == '>' {
		addr = addr[:len(addr)-1]
	}
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			return addr[:i], addr[i+1:]
		}
	}
	return addr, "unknown"
}
