// Package delivery provides a gRPC client for delivering messages to local
// mailboxes via session-manager's DeliveryService endpoint.
package delivery

import (
	"context"
	"fmt"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client delivers messages to local mailboxes via session-manager.
type Client struct {
	conn   *grpc.ClientConn
	client pb.DeliveryServiceClient
}

// NewClient creates a delivery client for the given gRPC target.
// For Unix sockets, use "unix:///path/to/socket".
// For TCP (testing), use "host:port".
func NewClient(target string) (*Client, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("creating gRPC client: %w", err)
	}
	return &Client{conn: conn, client: pb.NewDeliveryServiceClient(conn)}, nil
}

// newClientFromConn creates a delivery client from an existing gRPC connection.
// Used for testing with in-process servers.
func newClientFromConn(conn grpc.ClientConnInterface) *Client {
	return &Client{client: pb.NewDeliveryServiceClient(conn)}
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// DeliverDSN delivers a DSN bounce message to a local mailbox.
// The sender is empty (null sender per RFC 3461 §5.2.1).
// The recipient is the original submitter's address.
// The body is the complete RFC 822 DSN message.
func (c *Client) DeliverDSN(ctx context.Context, recipient string, body []byte) error {
	stream, err := c.client.Deliver(ctx)
	if err != nil {
		return fmt.Errorf("opening delivery stream: %w", err)
	}

	// Send metadata first.
	if err := stream.Send(&pb.DeliverRequest{
		Payload: &pb.DeliverRequest_Metadata{
			Metadata: &pb.DeliverMetadata{
				Sender:         "", // null sender for DSN
				Recipient:      recipient,
				ClientIp:       "127.0.0.1",
				ClientHostname: "queue-manager",
			},
		},
	}); err != nil {
		return fmt.Errorf("sending metadata: %w", err)
	}

	// Send body in 64KB chunks.
	const chunkSize = 64 * 1024
	for i := 0; i < len(body); i += chunkSize {
		end := i + chunkSize
		if end > len(body) {
			end = len(body)
		}
		if err := stream.Send(&pb.DeliverRequest{
			Payload: &pb.DeliverRequest_Data{
				Data: body[i:end],
			},
		}); err != nil {
			return fmt.Errorf("sending body chunk: %w", err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("delivery response: %w", err)
	}

	if resp.Result != pb.DeliverResult_DELIVER_RESULT_DELIVERED {
		return fmt.Errorf("delivery rejected: %s (temporary=%v)", resp.Reason, resp.Temporary)
	}

	return nil
}
