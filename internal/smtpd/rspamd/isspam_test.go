package rspamd

import (
	"encoding/json"
	"testing"

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// TestConvertResult_IsSpamFromAction covers the regression in #250: rspamd's
// /checkv2 response carries no is_spam key, so decoding it left IsSpam false on
// every message however it scored. The verdict has to come from the action,
// which is what rspamd actually decided (and what rspamc derives its own
// "Spam: true" line from).
func TestConvertResult_IsSpamFromAction(t *testing.T) {
	c := &Checker{}

	tests := []struct {
		action RspamdAction
		want   bool
		why    string
	}{
		{RspamdActionAddHeader, true, "flagged and delivered -- the band this whole feature exists for"},
		{RspamdActionRewriteSubject, true, "flagged and delivered, subject annotated"},
		{RspamdActionReject, true, "spam, refused at SMTP"},
		{RspamdActionNoAction, false, "clean"},
		// Deferrals are not a spam verdict: the message has not been judged yet,
		// and greylisting in particular fires on messages that turn out clean.
		{RspamdActionGreylist, false, "deferred, not judged"},
		{RspamdActionSoftReject, false, "deferred, not judged"},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			got := c.convertResult(&RspamdResult{
				Action:        tt.action,
				Score:         9,
				RequiredScore: 15,
			}, spamcheck.CheckOptions{})
			if got.IsSpam != tt.want {
				t.Errorf("action %q: IsSpam = %v, want %v (%s)", tt.action, got.IsSpam, tt.want, tt.why)
			}
		})
	}
}

// TestConvertResult_IsSpamFromRealResponse decodes a response shaped like the
// one rspamd actually returns -- no is_spam key at all -- rather than
// constructing the struct by hand. Building it in Go would set the field
// explicitly and hide the exact bug this guards.
func TestConvertResult_IsSpamFromRealResponse(t *testing.T) {
	const body = `{"score":10.3,"required_score":15.0,"action":"add header","symbols":{}}`

	var r RspamdResult
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.IsSpam {
		t.Fatal("precondition failed: the wire format is expected to omit is_spam")
	}

	result := (&Checker{}).convertResult(&r, spamcheck.CheckOptions{})
	if !result.IsSpam {
		t.Error("a flagged message decoded from a real response is not marked spam")
	}
	if got := result.Headers["X-Spam-Flag"]; got != "YES" {
		t.Errorf("X-Spam-Flag = %q, want YES", got)
	}
	if got := result.Headers["X-Spam-Status"]; got == "" || got[:3] != "Yes" {
		t.Errorf("X-Spam-Status = %q, want it to begin with Yes", got)
	}
}

// TestConvertResult_HonorsExplicitIsSpam: if a future rspamd, or the /checkv3
// migration (#124), does send the field, a true value is not thrown away by the
// action-derived default.
func TestConvertResult_HonorsExplicitIsSpam(t *testing.T) {
	result := (&Checker{}).convertResult(&RspamdResult{
		Action:        RspamdActionNoAction,
		IsSpam:        true,
		Score:         3,
		RequiredScore: 15,
	}, spamcheck.CheckOptions{})

	if !result.IsSpam {
		t.Error("an explicit is_spam:true was discarded")
	}
}
