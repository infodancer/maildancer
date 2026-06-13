package client

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

// DeliveryResult mirrors deliver.DeliverResult for callers that need structured results.
type DeliveryResult int

const (
	// Delivered means the message was successfully written to the maildir.
	Delivered DeliveryResult = iota
	// Rejected means delivery was refused.
	Rejected
	// Redirected means the message should be re-delivered to different addresses.
	Redirected
)

// DeliveryResponse holds the structured outcome of a delivery attempt.
type DeliveryResponse struct {
	Result            DeliveryResult
	Temporary         bool
	Reason            string
	RedirectAddresses []string
}

// DeliveryClient connects to a mail-session gRPC server for message delivery.
// It calls the DeliveryService.Deliver RPC and returns structured results
// including redirect addresses (fixing smtpd's silent-drop bug).
type DeliveryClient struct {
	conn     *grpc.ClientConn
	delivery pb.DeliveryServiceClient
}

// DialDelivery connects to a mail-session gRPC server for delivery operations.
func DialDelivery(socketPath string) (*DeliveryClient, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", socketPath, err)
	}
	return &DeliveryClient{
		conn:     conn,
		delivery: pb.NewDeliveryServiceClient(conn),
	}, nil
}

// Close closes the underlying gRPC connection.
func (d *DeliveryClient) Close() error {
	return d.conn.Close()
}

// DeliveryMetadata holds the envelope information for a delivery request.
type DeliveryMetadata struct {
	Sender         string
	Recipient      string
	ClientIP       string
	ClientHostname string
	Forwarded      bool
	ReceivedTime   string
}

// Deliver sends a message through the delivery pipeline and returns the structured result.
// The message body is streamed in 64KB chunks.
func (d *DeliveryClient) Deliver(ctx context.Context, meta DeliveryMetadata, message io.Reader) (*DeliveryResponse, error) {
	stream, err := d.delivery.Deliver(ctx)
	if err != nil {
		return nil, fmt.Errorf("open deliver stream: %w", err)
	}

	// Send metadata first.
	if err := stream.Send(&pb.DeliverRequest{
		Payload: &pb.DeliverRequest_Metadata{
			Metadata: &pb.DeliverMetadata{
				Sender:         meta.Sender,
				Recipient:      meta.Recipient,
				ClientIp:       meta.ClientIP,
				ClientHostname: meta.ClientHostname,
				Forwarded:      meta.Forwarded,
				ReceivedTime:   meta.ReceivedTime,
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("send metadata: %w", err)
	}

	// Stream body in 64KB chunks.
	buf := make([]byte, 64*1024)
	for {
		n, readErr := message.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.DeliverRequest{
				Payload: &pb.DeliverRequest_Data{Data: buf[:n]},
			}); err != nil {
				return nil, fmt.Errorf("send body chunk: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read message: %w", readErr)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, fmt.Errorf("close deliver stream: %w", err)
	}

	result := &DeliveryResponse{
		Temporary:         resp.GetTemporary(),
		Reason:            resp.GetReason(),
		RedirectAddresses: resp.GetRedirectAddresses(),
	}
	switch resp.GetResult() {
	case pb.DeliverResult_DELIVER_RESULT_DELIVERED:
		result.Result = Delivered
	case pb.DeliverResult_DELIVER_RESULT_REJECTED:
		result.Result = Rejected
	case pb.DeliverResult_DELIVER_RESULT_REDIRECTED:
		result.Result = Redirected
	}

	return result, nil
}
