package smtp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// SessionManagerDeliveryAgent implements msgstore.DeliveryAgent by calling the
// session-manager's DeliveryService over gRPC. The session-manager proxies the
// request to a oneshot mail-session subprocess, handling credential lookup and
// process isolation.
type SessionManagerDeliveryAgent struct {
	conn     *grpc.ClientConn
	delivery pb.DeliveryServiceClient
	logger   *slog.Logger
}

// NewSessionManagerDeliveryAgent connects to the session-manager and returns a
// delivery agent. Supports unix socket (insecure) and TCP+mTLS.
func NewSessionManagerDeliveryAgent(cfg config.SessionManagerConfig, logger *slog.Logger) (*SessionManagerDeliveryAgent, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var target string
	var creds grpc.DialOption

	if cfg.Socket != "" {
		target = "unix://" + cfg.Socket
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else if cfg.Address != "" {
		target = cfg.Address
		tlsCfg, err := buildClientTLS(cfg.CACert, cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("session-manager mTLS: %w", err)
		}
		creds = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	} else {
		return nil, fmt.Errorf("session-manager: socket or address required")
	}

	conn, err := grpc.NewClient(target, creds)
	if err != nil {
		return nil, fmt.Errorf("session-manager dial %q: %w", target, err)
	}

	logger.Info("session-manager delivery agent connected", "target", target)

	return &SessionManagerDeliveryAgent{
		conn:     conn,
		delivery: pb.NewDeliveryServiceClient(conn),
		logger:   logger,
	}, nil
}

// Deliver sends the message to the session-manager for delivery to the recipient.
func (a *SessionManagerDeliveryAgent) Deliver(ctx context.Context, envelope msgstore.Envelope, message io.Reader) error {
	if len(envelope.Recipients) == 0 {
		return fmt.Errorf("session-manager delivery: no recipients")
	}

	recipient := envelope.Recipients[0]

	stream, err := a.delivery.Deliver(ctx)
	if err != nil {
		return fmt.Errorf("session-manager delivery: open stream: %w", err)
	}

	// Send metadata.
	meta := &pb.DeliverMetadata{
		Sender:    envelope.From,
		Recipient: recipient,
	}
	if envelope.ClientIP != nil {
		meta.ClientIp = envelope.ClientIP.String()
	}
	meta.ClientHostname = envelope.ClientHostname
	if !envelope.ReceivedTime.IsZero() {
		meta.ReceivedTime = envelope.ReceivedTime.Format(time.RFC3339)
	}

	if err := stream.Send(&pb.DeliverRequest{
		Payload: &pb.DeliverRequest_Metadata{Metadata: meta},
	}); err != nil {
		return fmt.Errorf("session-manager delivery: send metadata: %w", err)
	}

	// Stream body in 64KB chunks.
	buf := make([]byte, 64*1024)
	for {
		n, readErr := message.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.DeliverRequest{
				Payload: &pb.DeliverRequest_Data{Data: buf[:n]},
			}); err != nil {
				return fmt.Errorf("session-manager delivery: send body: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("session-manager delivery: read message: %w", readErr)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("session-manager delivery: close stream: %w", err)
	}

	switch resp.GetResult() {
	case pb.DeliverResult_DELIVER_RESULT_DELIVERED:
		a.logger.Debug("session-manager delivery complete", slog.String("recipient", recipient))
		return nil

	case pb.DeliverResult_DELIVER_RESULT_REJECTED:
		code := "550"
		if resp.GetTemporary() {
			code = "451"
		}
		a.logger.Debug("session-manager delivery rejected",
			slog.String("recipient", recipient),
			slog.String("code", code),
			slog.String("reason", resp.GetReason()))
		return fmt.Errorf("delivery rejected (%s): %s", code, resp.GetReason())

	case pb.DeliverResult_DELIVER_RESULT_REDIRECTED:
		a.logger.Info("session-manager delivery redirected",
			slog.String("recipient", recipient),
			slog.Int("redirect_count", len(resp.GetRedirectAddresses())),
			slog.String("addresses", strings.Join(resp.GetRedirectAddresses(), ", ")))
		return &RedirectError{
			Addresses: resp.GetRedirectAddresses(),
			Temporary: resp.GetTemporary(),
		}

	default:
		return fmt.Errorf("session-manager delivery: unknown result %d", resp.GetResult())
	}
}

// Close closes the gRPC connection to the session-manager.
func (a *SessionManagerDeliveryAgent) Close() error {
	return a.conn.Close()
}

// buildClientTLS creates a TLS config for connecting to the session-manager with mTLS.
func buildClientTLS(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA cert contains no valid certificates")
	}

	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Compile-time checks.
var (
	_ msgstore.DeliveryAgent = (*SessionManagerDeliveryAgent)(nil)
	_ io.Closer              = (*SessionManagerDeliveryAgent)(nil)
)
