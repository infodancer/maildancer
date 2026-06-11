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
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// SessionManagerDeliveryAgent delivers messages via the session-manager's
// DeliveryService gRPC endpoint. The session-manager proxies the request to a
// oneshot mail-session subprocess, handling credential lookup and process
// isolation.
//
// This agent has no dependency on msgstore -- it speaks the mail-session proto
// directly. SMTP envelope fields are passed individually, not as a store type.
type SessionManagerDeliveryAgent struct {
	conn     *grpc.ClientConn
	delivery pb.DeliveryServiceClient
	outbound pb.OutboundServiceClient
	session  smpb.SessionServiceClient
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
		outbound: pb.NewOutboundServiceClient(conn),
		session:  smpb.NewSessionServiceClient(conn),
		logger:   logger,
	}, nil
}

// LoginResult holds the result of a session-manager Login call.
type LoginResult struct {
	Token           string
	Mailbox         string
	Extension       string
	MaxSendsPerHour int
}

// Login authenticates a user via session-manager and returns the auth result.
func (a *SessionManagerDeliveryAgent) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	resp, err := a.session.Login(ctx, &smpb.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Token:           resp.SessionToken,
		Mailbox:         resp.Mailbox,
		Extension:       resp.Extension,
		MaxSendsPerHour: int(resp.MaxSendsPerHour),
	}, nil
}

// Logout releases a session token in session-manager.
func (a *SessionManagerDeliveryAgent) Logout(ctx context.Context, token string) {
	_, err := a.session.Logout(ctx, &smpb.LogoutRequest{SessionToken: token})
	if err != nil {
		a.logger.Debug("session-manager logout error", slog.String("error", err.Error()))
	}
}

// ValidateRecipientResult holds the result of a ValidateRecipient call.
type ValidateRecipientResult struct {
	DomainIsLocal  bool
	UserExists     bool
	DeferRejection bool
}

// ValidateRecipient checks whether a recipient address is deliverable.
func (a *SessionManagerDeliveryAgent) ValidateRecipient(ctx context.Context, address string) (*ValidateRecipientResult, error) {
	resp, err := a.session.ValidateRecipient(ctx, &smpb.ValidateRecipientRequest{
		Address: address,
	})
	if err != nil {
		return nil, err
	}
	return &ValidateRecipientResult{
		DomainIsLocal:  resp.DomainIsLocal,
		UserExists:     resp.UserExists,
		DeferRejection: resp.DeferRejection,
	}, nil
}

// Deliver sends a message to the session-manager for delivery.
// Parameters map directly to SMTP envelope fields -- no msgstore types involved.
func (a *SessionManagerDeliveryAgent) Deliver(ctx context.Context, sender, recipient, clientIP, clientHostname string, receivedTime time.Time, message io.Reader) error {
	stream, err := a.delivery.Deliver(ctx)
	if err != nil {
		return fmt.Errorf("session-manager delivery: open stream: %w", err)
	}

	meta := &pb.DeliverMetadata{
		Sender:         sender,
		Recipient:      recipient,
		ClientIp:       clientIP,
		ClientHostname: clientHostname,
	}
	if !receivedTime.IsZero() {
		meta.ReceivedTime = receivedTime.Format(time.RFC3339)
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

// Enqueue sends a message to the session-manager's OutboundService for queue
// injection. The session-manager handles DKIM signing and envelope generation.
func (a *SessionManagerDeliveryAgent) Enqueue(ctx context.Context, sender string, recipients []string, message io.Reader) (string, error) {
	stream, err := a.outbound.Enqueue(ctx)
	if err != nil {
		return "", fmt.Errorf("session-manager enqueue: open stream: %w", err)
	}

	// Send metadata.
	if err := stream.Send(&pb.EnqueueRequest{
		Payload: &pb.EnqueueRequest_Metadata{
			Metadata: &pb.EnqueueMetadata{
				Sender:     sender,
				Recipients: recipients,
			},
		},
	}); err != nil {
		return "", fmt.Errorf("session-manager enqueue: send metadata: %w", err)
	}

	// Stream body in 64KB chunks.
	buf := make([]byte, 64*1024)
	for {
		n, readErr := message.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.EnqueueRequest{
				Payload: &pb.EnqueueRequest_Data{Data: buf[:n]},
			}); err != nil {
				return "", fmt.Errorf("session-manager enqueue: send body: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("session-manager enqueue: read message: %w", readErr)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return "", fmt.Errorf("session-manager enqueue: close stream: %w", err)
	}

	a.logger.Debug("message enqueued via session-manager",
		slog.String("msgid", resp.GetMessageId()),
		slog.String("sender", sender),
		slog.Int("recipients", len(recipients)))

	return resp.GetMessageId(), nil
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
