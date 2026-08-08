package grpcserver

import (
	"testing"

	pb "github.com/infodancer/maildancer/internal/mail-session/proto/mailsession/v1"
)

func TestDeliverRequestFromMetadata_NoVerdict(t *testing.T) {
	req := deliverRequestFromMetadata(&pb.DeliverMetadata{
		Sender:    "s@example.com",
		Recipient: "r@example.com",
		Msgid:     "abc",
	})
	if req.Sender != "s@example.com" || req.Recipient != "r@example.com" || req.MsgID != "abc" {
		t.Errorf("basic fields not mapped: %+v", req)
	}
	if req.Spam != nil {
		t.Errorf("Spam = %+v, want nil when no verdict on the wire", req.Spam)
	}
}

func TestDeliverRequestFromMetadata_WithVerdict(t *testing.T) {
	req := deliverRequestFromMetadata(&pb.DeliverMetadata{
		Recipient: "r@example.com",
		SpamVerdict: &pb.SpamVerdict{
			IsSpam:  true,
			Score:   8.2,
			Headers: map[string]string{"X-Spam-Flag": "YES"},
		},
	})
	if req.Spam == nil {
		t.Fatal("Spam = nil, want a verdict")
	}
	if !req.Spam.IsSpam {
		t.Error("IsSpam = false, want true")
	}
	if req.Spam.Score != 8.2 {
		t.Errorf("Score = %v, want 8.2", req.Spam.Score)
	}
	if req.Spam.Headers["X-Spam-Flag"] != "YES" {
		t.Errorf("Headers[X-Spam-Flag] = %q, want YES", req.Spam.Headers["X-Spam-Flag"])
	}
}

func TestDeliverRequestFromMetadata_CleanVerdictIsNotNil(t *testing.T) {
	req := deliverRequestFromMetadata(&pb.DeliverMetadata{
		SpamVerdict: &pb.SpamVerdict{IsSpam: false, Score: 0.1},
	})
	if req.Spam == nil {
		t.Fatal("a scanned-clean verdict must survive as non-nil")
	}
	if req.Spam.IsSpam {
		t.Error("IsSpam = true, want false")
	}
}
