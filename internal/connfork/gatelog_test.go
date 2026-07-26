package connfork

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer makes a log buffer safe for the dispatcher's accept and reaper
// goroutines, which may still be writing at assertion time. Mirrors the helper
// the pop3d/imapd/smtpd dispatcher tests use for the same reason.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// findRecord returns the first log record whose "msg" begins with prefix.
// JSON rather than text output so an attribute assertion is exact: a text
// handler renders `listener=127.0.0.1:9` and a substring match on that would
// also be satisfied by an unrelated key ending in "listener".
func findRecord(t *testing.T, buf *lockedBuffer, prefix string) map[string]any {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		for line := range strings.SplitSeq(buf.String(), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			if msg, ok := rec["msg"].(string); ok && strings.HasPrefix(msg, prefix) {
				return rec
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log record with msg prefix %q within 5s; log was:\n%s",
				prefix, buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGateLog_EveryVerdictIsAttributedToItsListener is #227. smtpd serves 25,
// 465 and 587 from one process, so a gate decision that names only the client
// address cannot be attributed to the port it happened on -- which is exactly
// the question the #225 ban-scope data has to answer. The shadow branch was
// written with attribution in mind and the older deny and error branches were
// not; this pins all three together so they cannot drift apart again.
func TestGateLog_EveryVerdictIsAttributedToItsListener(t *testing.T) {
	tests := []struct {
		name    string
		gate    *fakeGate
		msg     string
		wantKey map[string]string
	}{
		{
			name: "denied connection",
			gate: &fakeGate{verdict: Verdict{Banned: true, Reason: "banned"}},
			msg:  "connection denied by peer gate",
			wantKey: map[string]string{
				"client_ip": "127.0.0.1",
				"reason":    "banned",
			},
		},
		{
			name: "shadow-banned connection",
			gate: &fakeGate{verdict: Verdict{ShadowBanned: true, Reason: "banned"}},
			msg:  "peer would have been denied",
			wantKey: map[string]string{
				"client_ip": "127.0.0.1",
				"reason":    "banned",
			},
		},
		{
			name: "gate error",
			gate: &fakeGate{err: errors.New("gate unreachable")},
			msg:  "peer gate check failed",
			wantKey: map[string]string{
				"client_ip": "127.0.0.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &lockedBuffer{}
			var listenAddr, listenMode string

			h := newGateHarness(t, func(cfg *Config) {
				cfg.Gate = tt.gate
				cfg.Logger = slog.New(slog.NewJSONHandler(buf,
					&slog.HandlerOptions{Level: slog.LevelDebug}))
				cfg.Listeners[0].Mode = "submission"
				listenAddr = cfg.Listeners[0].Address
				listenMode = cfg.Listeners[0].Mode
			})

			conn, err := net.Dial("tcp", h.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = conn.Close()

			rec := findRecord(t, buf, tt.msg)

			// Every gate decision must name the listener that produced it.
			if got := rec["listener"]; got != listenAddr {
				t.Errorf("listener = %v, want %q (log: %v)", got, listenAddr, rec)
			}
			if got := rec["mode"]; got != listenMode {
				t.Errorf("mode = %v, want %q (log: %v)", got, listenMode, rec)
			}
			for key, want := range tt.wantKey {
				if got := rec[key]; got != want {
					t.Errorf("%s = %v, want %q", key, got, want)
				}
			}
		})
	}
}
