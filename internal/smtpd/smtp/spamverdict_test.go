package smtp

import (
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

func TestSpamVerdictProto_Nil(t *testing.T) {
	// No check ran -> nil verdict, so the delivery side can tell "not scanned"
	// apart from "scanned and clean".
	if got := spamVerdictProto(nil); got != nil {
		t.Errorf("spamVerdictProto(nil) = %+v, want nil", got)
	}
}

func TestSpamVerdictProto_Populated(t *testing.T) {
	r := &spamcheck.CheckResult{
		IsSpam: true,
		Score:  8.2,
		Headers: map[string]string{
			"X-Spam-Flag":  "YES",
			"X-Spam-Score": "8.20",
		},
	}
	got := spamVerdictProto(r)
	if got == nil {
		t.Fatal("spamVerdictProto returned nil for a populated result")
	}
	if !got.GetIsSpam() {
		t.Error("IsSpam = false, want true")
	}
	if got.GetScore() != 8.2 {
		t.Errorf("Score = %v, want 8.2", got.GetScore())
	}
	if got.GetHeaders()["X-Spam-Flag"] != "YES" {
		t.Errorf("Headers[X-Spam-Flag] = %q, want YES", got.GetHeaders()["X-Spam-Flag"])
	}
}

func TestSpamVerdictProto_CleanIsNotNil(t *testing.T) {
	// A scanned-clean message carries a non-nil verdict with IsSpam=false.
	got := spamVerdictProto(&spamcheck.CheckResult{IsSpam: false, Score: 0.1})
	if got == nil {
		t.Fatal("clean result must produce a non-nil verdict")
	}
	if got.GetIsSpam() {
		t.Error("IsSpam = true, want false")
	}
}
