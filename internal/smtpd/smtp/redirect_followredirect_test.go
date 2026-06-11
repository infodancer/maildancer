package smtp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/infodancer/maildancer/internal/smtpd/config"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

// deliverCall records a single DeliveryService.Deliver invocation.
type deliverCall struct {
	recipient string
	forwarded bool
}

// enqueueCall records a single OutboundService.Enqueue invocation.
type enqueueCall struct {
	recipients []string
}

// combinedMockServer implements DeliveryService, OutboundService, and
// SessionService on one socket so followRedirect can be driven end to end.
//
// validateLocal decides DomainIsLocal per recipient address (default true when
// absent). The first Deliver for the original recipient returns the configured
// redirect; re-submitted local Delivers (Forwarded=true) return DELIVERED unless
// secondRedirect is set, which makes a re-submitted local target itself redirect.
type combinedMockServer struct {
	pb.UnimplementedDeliveryServiceServer
	pb.UnimplementedOutboundServiceServer
	smpb.UnimplementedSessionServiceServer

	validateLocal   map[string]bool
	originalRcpt    string
	redirectTargets []string
	secondRedirect  bool

	mu       sync.Mutex
	delivers []deliverCall
	enqueues []enqueueCall
}

func (s *combinedMockServer) ValidateRecipient(_ context.Context, req *smpb.ValidateRecipientRequest) (*smpb.ValidateRecipientResponse, error) {
	local := true
	if v, ok := s.validateLocal[req.Address]; ok {
		local = v
	}
	return &smpb.ValidateRecipientResponse{
		DomainIsLocal: local,
		UserExists:    true,
	}, nil
}

func (s *combinedMockServer) Deliver(stream grpc.ClientStreamingServer[pb.DeliverRequest, pb.DeliverResponse]) error {
	var meta *pb.DeliverMetadata
	var body bytes.Buffer
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch p := req.Payload.(type) {
		case *pb.DeliverRequest_Metadata:
			meta = p.Metadata
		case *pb.DeliverRequest_Data:
			body.Write(p.Data)
		}
	}

	s.mu.Lock()
	s.delivers = append(s.delivers, deliverCall{
		recipient: meta.GetRecipient(),
		forwarded: meta.GetForwarded(),
	})
	s.mu.Unlock()

	// The original (non-forwarded) recipient resolves to a configured forward.
	if !meta.GetForwarded() && meta.GetRecipient() == s.originalRcpt {
		return stream.SendAndClose(&pb.DeliverResponse{
			Result:            pb.DeliverResult_DELIVER_RESULT_REDIRECTED,
			RedirectAddresses: s.redirectTargets,
		})
	}

	// A re-submitted local target that is itself a forward source (used to test
	// the one-hop ceiling).
	if meta.GetForwarded() && s.secondRedirect {
		return stream.SendAndClose(&pb.DeliverResponse{
			Result:            pb.DeliverResult_DELIVER_RESULT_REDIRECTED,
			RedirectAddresses: []string{"loop@example.com"},
		})
	}

	return stream.SendAndClose(&pb.DeliverResponse{
		Result: pb.DeliverResult_DELIVER_RESULT_DELIVERED,
	})
}

func (s *combinedMockServer) Enqueue(stream grpc.ClientStreamingServer[pb.EnqueueRequest, pb.EnqueueResponse]) error {
	var recipients []string
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if m, ok := req.Payload.(*pb.EnqueueRequest_Metadata); ok {
			recipients = m.Metadata.GetRecipients()
		}
	}

	s.mu.Lock()
	s.enqueues = append(s.enqueues, enqueueCall{recipients: recipients})
	s.mu.Unlock()

	return stream.SendAndClose(&pb.EnqueueResponse{MessageId: "msg-1"})
}

// startCombinedMockServer registers the combined mock on a temp unix socket and
// returns a connected SessionManagerDeliveryAgent.
func startCombinedMockServer(t *testing.T, mock *combinedMockServer) *SessionManagerDeliveryAgent {
	t.Helper()

	socketPath := t.TempDir() + "/combined.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gsrv := grpc.NewServer()
	pb.RegisterDeliveryServiceServer(gsrv, mock)
	pb.RegisterOutboundServiceServer(gsrv, mock)
	smpb.RegisterSessionServiceServer(gsrv, mock)
	go func() { _ = gsrv.Serve(ln) }()
	t.Cleanup(func() { gsrv.Stop() })

	agent, err := NewSessionManagerDeliveryAgent(config.SessionManagerConfig{
		Socket: socketPath,
	}, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	return agent
}

func newRedirectSession(t *testing.T, agent *SessionManagerDeliveryAgent) *Session {
	t.Helper()
	backend := &Backend{smDelivery: agent, logger: slog.Default()}
	return &Session{
		backend:    backend,
		logger:     slog.Default(),
		from:       "sender@external.com",
		recipients: []string{"alias@example.com"},
	}
}

// TestFollowRedirect_LocalTarget proves a configured forward to a local mailbox
// results in a local re-delivery with Forwarded=true (not a 451).
func TestFollowRedirect_LocalTarget(t *testing.T) {
	mock := &combinedMockServer{
		originalRcpt:    "alias@example.com",
		redirectTargets: []string{"bob@example.com"},
		validateLocal:   map[string]bool{"bob@example.com": true},
	}
	agent := startCombinedMockServer(t, mock)
	s := newRedirectSession(t, agent)

	redirect := &RedirectError{Addresses: []string{"bob@example.com"}}
	if err := s.followRedirect(context.Background(), redirect, memBuf("test body")); err != nil {
		t.Fatalf("followRedirect returned error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// The re-submission must have happened: a Deliver to the local target with
	// Forwarded=true.
	var found bool
	for _, c := range mock.delivers {
		if c.recipient == "bob@example.com" {
			found = true
			if !c.forwarded {
				t.Errorf("forward re-delivery to %q had Forwarded=false, want true", c.recipient)
			}
		}
	}
	if !found {
		t.Fatalf("no re-delivery to local forward target; delivers=%+v", mock.delivers)
	}
	if len(mock.enqueues) != 0 {
		t.Errorf("local forward target should not enqueue; enqueues=%+v", mock.enqueues)
	}
}

// TestFollowRedirect_ExternalTarget proves a configured forward to an external
// domain results in an outbound enqueue (not a 451).
func TestFollowRedirect_ExternalTarget(t *testing.T) {
	mock := &combinedMockServer{
		originalRcpt:    "alias@example.com",
		redirectTargets: []string{"matthew@gmail.com"},
		validateLocal:   map[string]bool{"matthew@gmail.com": false},
	}
	agent := startCombinedMockServer(t, mock)
	s := newRedirectSession(t, agent)

	redirect := &RedirectError{Addresses: []string{"matthew@gmail.com"}}
	if err := s.followRedirect(context.Background(), redirect, memBuf("test body")); err != nil {
		t.Fatalf("followRedirect returned error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.enqueues) != 1 {
		t.Fatalf("expected 1 enqueue for external forward, got %d (%+v)", len(mock.enqueues), mock.enqueues)
	}
	if len(mock.enqueues[0].recipients) != 1 || mock.enqueues[0].recipients[0] != "matthew@gmail.com" {
		t.Errorf("enqueue recipients = %v, want [matthew@gmail.com]", mock.enqueues[0].recipients)
	}
	// External target must not be delivered locally.
	for _, c := range mock.delivers {
		if c.recipient == "matthew@gmail.com" {
			t.Errorf("external forward target was delivered locally: %+v", c)
		}
	}
}

// TestFollowRedirect_OneHopCeiling proves smtpd follows at most one redirect: a
// re-submitted local target that itself redirects is a configuration error.
func TestFollowRedirect_OneHopCeiling(t *testing.T) {
	mock := &combinedMockServer{
		originalRcpt:    "alias@example.com",
		redirectTargets: []string{"bob@example.com"},
		validateLocal:   map[string]bool{"bob@example.com": true},
		secondRedirect:  true,
	}
	agent := startCombinedMockServer(t, mock)
	s := newRedirectSession(t, agent)

	redirect := &RedirectError{Addresses: []string{"bob@example.com"}}
	err := s.followRedirect(context.Background(), redirect, memBuf("test body"))
	if err == nil {
		t.Fatal("expected error for second redirect (1-hop limit), got nil")
	}
	if !strings.Contains(err.Error(), "1-hop") {
		t.Errorf("error = %q, want mention of 1-hop limit", err.Error())
	}
}

// memBuf returns a tempBuffer backed by an in-memory buffer for tests.
func memBuf(body string) tempBuffer {
	b := &memTempBuf{}
	b.buf.WriteString(body)
	return b
}

// TestData_ForwardDoesNotNotifyOriginalRecipient drives a full Data() with a
// configured forward to a local target and asserts the IMAP-IDLE notification
// goes to the forward target (bob) only -- the original recipient (alice), whose
// mail was forwarded away, must NOT be poked. This covers the outer-block skip
// in Data(), which the followRedirect-level tests cannot observe.
func TestData_ForwardDoesNotNotifyOriginalRecipient(t *testing.T) {
	mock := &combinedMockServer{
		originalRcpt:    "alice@example.com",
		redirectTargets: []string{"bob@example.com"},
		validateLocal:   map[string]bool{"bob@example.com": true},
	}
	agent := startCombinedMockServer(t, mock)

	// Real Notifier over miniredis so we can observe published channels.
	mr := miniredis.RunT(t)
	notifier, err := NewNotifier("redis://"+mr.Addr(), "", slog.Default())
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	t.Cleanup(func() { _ = notifier.Close() })

	ctx := context.Background()
	sub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = sub.Close() })
	aliceCh := MailChannel("alice@example.com")
	bobCh := MailChannel("bob@example.com")
	pubsub := sub.Subscribe(ctx, aliceCh, bobCh)
	t.Cleanup(func() { _ = pubsub.Close() })
	if _, err := pubsub.Receive(ctx); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	s := &Session{
		backend: &Backend{
			smDelivery: agent,
			notifier:   notifier,
			logger:     slog.Default(),
		},
		logger:       slog.Default(),
		from:         "sender@external.com",
		mailFromSeen: true,
		recipients:   []string{"alice@example.com"},
	}

	body := "Subject: test\r\n\r\nhello\r\n"
	if err := s.Data(strings.NewReader(body)); err != nil {
		t.Fatalf("Data returned error: %v", err)
	}

	// Collect published notifications with a short deadline. We expect exactly
	// one (bob); alice must never appear.
	recvCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var bobNotified, aliceNotified int
	for {
		msg, err := pubsub.ReceiveMessage(recvCtx)
		if err != nil {
			break // deadline reached -- no more messages
		}
		switch msg.Channel {
		case bobCh:
			bobNotified++
		case aliceCh:
			aliceNotified++
		}
	}

	if aliceNotified != 0 {
		t.Errorf("original recipient alice was notified %d time(s); want 0 (mail was forwarded away)", aliceNotified)
	}
	if bobNotified != 1 {
		t.Errorf("forward target bob notified %d time(s); want exactly 1", bobNotified)
	}
}
