package grpcserver

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/infodancer/maildancer/auth/domain"
	_ "github.com/infodancer/maildancer/auth/passwd"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/metrics"
	_ "github.com/infodancer/maildancer/msgstore/maildir"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// newForwardingProxyClient stands up a real in-process gRPC server hosting the
// deliveryProxy backed by a Manager whose domain provider reads a temp config
// tree. The domain has admin-tier ([forwards]) and domain-tier (forwards file)
// rules but no passwd entries, so every match is a forward-only address.
//
// MailSessionCmd points at a path that cannot execute: any code path that
// reaches the spawn fails loudly, so a clean REDIRECTED response proves the
// forward was resolved before -- and instead of -- the spawn.
func newForwardingProxyClient(t *testing.T) pb.DeliveryServiceClient {
	t.Helper()
	base := t.TempDir()
	domainDir := filepath.Join(base, "example.com")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `[auth]
type = "passwd"
credential_backend = "passwd"
key_backend = "keys"

[msgstore]
type = "maildir"
base_path = "users"

[forwards]
alias = "real@elsewhere.example.com"
twoways = "a@x.example.com,b@y.example.com"
`
	mustWrite(t, filepath.Join(domainDir, "config.toml"), cfg)
	mustWrite(t, filepath.Join(domainDir, "passwd"), "# no local mailboxes\n")
	mustWrite(t, filepath.Join(domainDir, "forwards"), "team:lead@elsewhere.example.com\n")

	provider := domain.NewFilesystemDomainProvider(base, nil)
	t.Cleanup(func() { _ = provider.Close() })

	mgr := manager.New(
		&config.Config{DomainsPath: base, MailSessionCmd: "/nonexistent/never-spawn"},
		domain.NewAuthRouter(provider, nil),
		provider,
		&metrics.NoopCollector{},
	)

	gsrv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(gsrv, &deliveryProxy{mgr: mgr, metrics: &metrics.NoopCollector{}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(gsrv.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewDeliveryServiceClient(conn)
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

// sendDelivery drives a full Deliver stream (metadata + body) and returns the
// final response (or error from CloseAndRecv).
func sendDelivery(t *testing.T, client pb.DeliveryServiceClient, meta *pb.DeliverMetadata) (*pb.DeliverResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Deliver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A Send may race the server terminating the RPC early: when a delivery
	// falls through to a failing spawn (e.g. a forwarded delivery that bypasses
	// redirect resolution), the handler returns before the client finishes
	// sending. gRPC surfaces that as io.EOF on Send, and the real status must be
	// read from CloseAndRecv -- so io.EOF here is expected, not a failure.
	if err := stream.Send(&pb.DeliverRequest{Payload: &pb.DeliverRequest_Metadata{Metadata: meta}}); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	// A body, to confirm the proxy drains it on the redirect path.
	if err := stream.Send(&pb.DeliverRequest{Payload: &pb.DeliverRequest_Data{Data: []byte("From: s@x\r\n\r\nhi\r\n")}}); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return stream.CloseAndRecv()
}

func TestDeliveryProxy_ForwardOnlyRedirects(t *testing.T) {
	client := newForwardingProxyClient(t)

	resp, err := sendDelivery(t, client, &pb.DeliverMetadata{
		Sender:    "sender@example.com",
		Recipient: "alias@example.com", // no mailbox, hence no uid
	})
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if resp.GetResult() != pb.DeliverResult_DELIVER_RESULT_REDIRECTED {
		t.Fatalf("result = %v, want REDIRECTED (reason %q)", resp.GetResult(), resp.GetReason())
	}
	if got := resp.GetRedirectAddresses(); len(got) != 1 || got[0] != "real@elsewhere.example.com" {
		t.Errorf("redirect addresses = %v, want [real@elsewhere.example.com]", got)
	}
}

func TestDeliveryProxy_DomainForwardsFileRedirects(t *testing.T) {
	client := newForwardingProxyClient(t)

	resp, err := sendDelivery(t, client, &pb.DeliverMetadata{
		Sender:    "sender@example.com",
		Recipient: "team@example.com",
	})
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if resp.GetResult() != pb.DeliverResult_DELIVER_RESULT_REDIRECTED {
		t.Fatalf("result = %v, want REDIRECTED", resp.GetResult())
	}
	if got := resp.GetRedirectAddresses(); len(got) != 1 || got[0] != "lead@elsewhere.example.com" {
		t.Errorf("redirect addresses = %v, want [lead@elsewhere.example.com]", got)
	}
}

func TestDeliveryProxy_MultiTargetTempFails(t *testing.T) {
	client := newForwardingProxyClient(t)

	resp, err := sendDelivery(t, client, &pb.DeliverMetadata{
		Sender:    "sender@example.com",
		Recipient: "twoways@example.com",
	})
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if resp.GetResult() != pb.DeliverResult_DELIVER_RESULT_REJECTED {
		t.Fatalf("result = %v, want REJECTED for multi-target", resp.GetResult())
	}
	if !resp.GetTemporary() {
		t.Error("want Temporary=true so the sending MTA holds while the admin fixes the 1:1 violation")
	}
	if resp.GetReason() == "" {
		t.Error("want a non-empty reason for the misconfiguration")
	}
}

// TestDeliveryProxy_ForwardedBypassesResolution proves the 1-hop guard: a
// re-submitted forward (Forwarded=true) is not resolved again. With resolution
// skipped, the proxy falls through to the spawn, which fails because the address
// has no mailbox and MailSessionCmd is bogus -- so the call errors rather than
// returning a (second) REDIRECTED.
func TestDeliveryProxy_ForwardedBypassesResolution(t *testing.T) {
	client := newForwardingProxyClient(t)

	resp, err := sendDelivery(t, client, &pb.DeliverMetadata{
		Sender:    "sender@example.com",
		Recipient: "alias@example.com",
		Forwarded: true,
	})
	if err == nil {
		t.Fatalf("want an error (no redirect, falls through to spawn), got result %v", resp.GetResult())
	}
}
