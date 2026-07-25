package passwd

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// newDecoyTestAgent builds an agent with exactly one real user.
func newDecoyTestAgent(t *testing.T) *Agent {
	t.Helper()

	hash, err := HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte("alice:"+hash+":alice\n"), 0600); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	agent, err := NewAgent(path, "")
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	return agent
}

func medianDuration(samples []time.Duration) time.Duration {
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// TestAuthenticate_UnknownUserCostsLikeWrongPassword pins the decoy verify
// (#206). Without it, an unknown account returns in microseconds while a real
// account costs a full argon2id derivation -- a timing oracle for account
// existence, measurable from a single request and independent of anything the
// response text says.
//
// session-manager's uniform failure deadline masks this at the RPC boundary,
// but only up to the deadline: once the work outlasts it, timing reflects the
// work again. So the two paths have to cost the same here as well, and this is
// the layer that can assert it directly.
func TestAuthenticate_UnknownUserCostsLikeWrongPassword(t *testing.T) {
	agent := newDecoyTestAgent(t)
	ctx := context.Background()

	// Warm the lazily built decoy hash so its one-time construction is not
	// charged to the first sample.
	_, _ = agent.Authenticate(ctx, "warmup", "x")

	const samples = 7
	var unknown, wrongPass []time.Duration
	for range samples {
		// Alternate so that machine load drifts affect both paths equally.
		start := time.Now()
		if _, err := agent.Authenticate(ctx, "nosuchuser", "whatever"); err != autherrors.ErrUserNotFound {
			t.Fatalf("unknown user error = %v, want ErrUserNotFound", err)
		}
		unknown = append(unknown, time.Since(start))

		start = time.Now()
		if _, err := agent.Authenticate(ctx, "alice", "wrong"); err != autherrors.ErrAuthFailed {
			t.Fatalf("wrong password error = %v, want ErrAuthFailed", err)
		}
		wrongPass = append(wrongPass, time.Since(start))
	}

	medUnknown, medWrong := medianDuration(unknown), medianDuration(wrongPass)

	// The real cost here is a 64 MB argon2id derivation, so both medians should
	// be milliseconds at least. If the unknown path were skipping it, it would
	// be orders of magnitude faster.
	if medUnknown < medWrong/2 {
		t.Errorf("unknown-user median %v is far below the wrong-password median %v; "+
			"the decoy verify is not running", medUnknown, medWrong)
	}

	// Neither should be trivially fast, which would mean the harness is not
	// exercising argon2id at all and the comparison above is meaningless.
	if medWrong < time.Millisecond {
		t.Fatalf("wrong-password median %v is implausibly fast; the test is not "+
			"measuring a real password verification", medWrong)
	}
}

// TestAuthenticate_UnknownUserStillReportsNotFound guards the obvious
// regression: the decoy must not change what the caller learns. auth/domain
// needs ErrUserNotFound to fire rule 1, and session-manager maps every failure
// to the same client-visible response regardless.
func TestAuthenticate_UnknownUserStillReportsNotFound(t *testing.T) {
	agent := newDecoyTestAgent(t)

	_, err := agent.Authenticate(context.Background(), "nosuchuser", "whatever")
	if err != autherrors.ErrUserNotFound {
		t.Errorf("error = %v, want ErrUserNotFound", err)
	}
}

// TestAuthenticate_RealUserStillSucceeds is the sanity check that the decoy did
// not disturb the working path.
func TestAuthenticate_RealUserStillSucceeds(t *testing.T) {
	agent := newDecoyTestAgent(t)

	session, err := agent.Authenticate(context.Background(), "alice", "correct-horse")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session.User == nil || session.User.Username != "alice" {
		t.Errorf("session = %+v, want alice", session)
	}
}

// TestDecoyHash_IsAVerifiableHash makes sure the decoy actually exercises the
// verifier rather than being rejected early by the format check -- an
// unparseable decoy would return immediately and defeat the whole point.
func TestDecoyHash_IsAVerifiableHash(t *testing.T) {
	hash := decoyHash()
	if hash == "" {
		t.Fatal("decoy hash is empty")
	}

	agent := newDecoyTestAgent(t)
	// The password is random and discarded, so this must fail -- but it must
	// fail after doing the derivation, not by bailing on the format.
	if agent.verifyPassword("definitely-not-the-decoy-password", hash) {
		t.Error("decoy hash verified against an arbitrary password")
	}

	start := time.Now()
	agent.decoyVerify("some-password")
	if elapsed := time.Since(start); elapsed < time.Millisecond {
		t.Errorf("decoyVerify returned in %v; it is not performing a derivation", elapsed)
	}
}

// TestDecoyHash_IsStable keeps the decoy from being rebuilt per call, which
// would make unknown-account attempts cost two derivations instead of one and
// reintroduce an asymmetry in the other direction.
func TestDecoyHash_IsStable(t *testing.T) {
	first := decoyHash()
	second := decoyHash()
	if first != second {
		t.Errorf("decoy hash changes between calls:\n first  = %q\n second = %q", first, second)
	}
}
