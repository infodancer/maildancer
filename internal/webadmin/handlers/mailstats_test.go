package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infodancer/maildancer/internal/webadmin/promclient"
	"log/slog"
)

// fakePrometheus builds an httptest.Server that returns canned vector results
// keyed by PromQL query string.
func fakePrometheus(t *testing.T, responses map[string][]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		results, ok := responses[query]
		if !ok {
			results = []map[string]any{}
		}
		resp := map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": results},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func promSample(metric map[string]string, value string) map[string]any {
	return map[string]any{"metric": metric, "value": []any{0, value}}
}

func TestHandleGetMailStats_Available(t *testing.T) {
	srv := fakePrometheus(t, map[string][]map[string]any{
		"smtpd_connections_active": {promSample(nil, "3")},
		"pop3d_connections_active": {promSample(nil, "1")},
		"imapd_connections_active": {promSample(nil, "5")},
		`sum(increase(smtpd_messages_received_total[24h]))`: {promSample(nil, "100")},
		`sum by (recipient_domain)(increase(smtpd_messages_received_total[24h]))`: {
			promSample(map[string]string{"recipient_domain": "example.com"}, "80"),
			promSample(map[string]string{"recipient_domain": "other.com"}, "20"),
		},
		`sum by (result)(increase(smtpd_rspamd_checks_total[24h]))`: {
			promSample(map[string]string{"result": "ham"}, "70"),
			promSample(map[string]string{"result": "spam"}, "20"),
			promSample(map[string]string{"result": "soft_reject"}, "7"),
			promSample(map[string]string{"result": "greylist"}, "3"),
		},
		`sum(increase(smtpd_messages_rejected_total[24h]))`: {promSample(nil, "15")},
		`sum by (result)(increase(smtpd_deliveries_total[24h]))`: {
			promSample(map[string]string{"result": "success"}, "98"),
			promSample(map[string]string{"result": "temp_failure"}, "1"),
			promSample(map[string]string{"result": "perm_failure"}, "1"),
		},
	})
	defer srv.Close()

	h := NewMailStatsHandler(promclient.New([]string{srv.URL}), nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/mailstats", nil)
	rr := httptest.NewRecorder()
	h.HandleGetMailStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var resp mailStatsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.Available {
		t.Fatal("expected available=true")
	}
	if resp.ActiveConnections.SMTP != 3 {
		t.Errorf("smtp active = %v, want 3", resp.ActiveConnections.SMTP)
	}
	if resp.ActiveConnections.POP3 != 1 {
		t.Errorf("pop3 active = %v, want 1", resp.ActiveConnections.POP3)
	}
	if resp.ActiveConnections.IMAP != 5 {
		t.Errorf("imap active = %v, want 5", resp.ActiveConnections.IMAP)
	}
	if resp.Incoming24h.Total != 100 {
		t.Errorf("incoming total = %v, want 100", resp.Incoming24h.Total)
	}
	if len(resp.Incoming24h.ByDomain) != 2 {
		t.Errorf("by_domain len = %d, want 2", len(resp.Incoming24h.ByDomain))
	}
	// Sorted descending by count: example.com first.
	if resp.Incoming24h.ByDomain[0].Domain != "example.com" {
		t.Errorf("top domain = %q, want example.com", resp.Incoming24h.ByDomain[0].Domain)
	}
	if resp.Verdict24h.Ham != 70 {
		t.Errorf("ham = %v, want 70", resp.Verdict24h.Ham)
	}
	if resp.Verdict24h.Spam != 20 {
		t.Errorf("spam = %v, want 20", resp.Verdict24h.Spam)
	}
	if resp.Verdict24h.Maybe != 10 { // soft_reject(7) + greylist(3)
		t.Errorf("maybe = %v, want 10", resp.Verdict24h.Maybe)
	}
	if resp.AcceptReject24h.Rejected != 15 {
		t.Errorf("rejected = %v, want 15", resp.AcceptReject24h.Rejected)
	}
	if resp.Delivery24h.Success != 98 {
		t.Errorf("delivery success = %v, want 98", resp.Delivery24h.Success)
	}
}

func TestHandleGetMailStats_Unavailable(t *testing.T) {
	h := NewMailStatsHandler(promclient.New([]string{}), nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/api/mailstats", nil)
	rr := httptest.NewRecorder()
	h.HandleGetMailStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp mailStatsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Available {
		t.Error("expected available=false when no Prometheus URLs configured")
	}
}
