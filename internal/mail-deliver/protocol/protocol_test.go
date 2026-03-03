package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/infodancer/maildancer/internal/mail-deliver/protocol"
)

func TestDeliverRequest_RoundTrip(t *testing.T) {
	req := protocol.DeliverRequest{
		Version:        protocol.Version,
		Sender:         "sender@example.com",
		Recipients:     []string{"user@domain.com"},
		ReceivedTime:   "2026-01-01T00:00:00Z",
		ClientIP:       "192.0.2.1",
		ClientHostname: "mail.example.com",
		Forwarded:      false,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got protocol.DeliverRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Version != req.Version {
		t.Errorf("Version: got %d, want %d", got.Version, req.Version)
	}
	if got.Sender != req.Sender {
		t.Errorf("Sender: got %q, want %q", got.Sender, req.Sender)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != req.Recipients[0] {
		t.Errorf("Recipients: got %v, want %v", got.Recipients, req.Recipients)
	}
	if got.Forwarded != req.Forwarded {
		t.Errorf("Forwarded: got %v, want %v", got.Forwarded, req.Forwarded)
	}
}

func TestDeliverRequest_ForwardedOmitEmpty(t *testing.T) {
	req := protocol.DeliverRequest{
		Version:    protocol.Version,
		Recipients: []string{"user@domain.com"},
		Forwarded:  false,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Forwarded=false should be omitted from JSON (omitempty).
	if string(data) != `{"version":1,"sender":"","recipients":["user@domain.com"]}` {
		// Allow any valid JSON without "forwarded" key.
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["forwarded"]; ok {
			t.Errorf("forwarded=false should be omitted, got %s", data)
		}
	}
}

func TestDeliverResponse_Results(t *testing.T) {
	cases := []struct {
		name string
		resp protocol.DeliverResponse
	}{
		{
			name: "delivered",
			resp: protocol.DeliverResponse{Version: protocol.Version, Result: protocol.ResultDelivered},
		},
		{
			name: "rejected permanent",
			resp: protocol.DeliverResponse{
				Version:   protocol.Version,
				Result:    protocol.ResultRejected,
				Temporary: false,
				Reason:    "spam",
			},
		},
		{
			name: "rejected temporary",
			resp: protocol.DeliverResponse{
				Version:   protocol.Version,
				Result:    protocol.ResultRejected,
				Temporary: true,
				Reason:    "rspamd unavailable",
			},
		},
		{
			name: "redirected single",
			resp: protocol.DeliverResponse{
				Version:   protocol.Version,
				Result:    protocol.ResultRedirected,
				Addresses: []string{"other@domain.com"},
			},
		},
		{
			name: "redirected multiple",
			resp: protocol.DeliverResponse{
				Version:   protocol.Version,
				Result:    protocol.ResultRedirected,
				Addresses: []string{"a@domain.com", "b@domain.com"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got protocol.DeliverResponse
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Version != tc.resp.Version {
				t.Errorf("Version: got %d, want %d", got.Version, tc.resp.Version)
			}
			if got.Result != tc.resp.Result {
				t.Errorf("Result: got %q, want %q", got.Result, tc.resp.Result)
			}
			if got.Temporary != tc.resp.Temporary {
				t.Errorf("Temporary: got %v, want %v", got.Temporary, tc.resp.Temporary)
			}
			if len(got.Addresses) != len(tc.resp.Addresses) {
				t.Errorf("Addresses len: got %d, want %d", len(got.Addresses), len(tc.resp.Addresses))
			}
		})
	}
}

func TestVersion(t *testing.T) {
	if protocol.Version != 1 {
		t.Errorf("Version = %d, want 1", protocol.Version)
	}
}
