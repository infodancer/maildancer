package grpcserver

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/session-manager/config"
	"github.com/infodancer/maildancer/internal/session-manager/manager"
	"github.com/infodancer/maildancer/internal/session-manager/peerfilter"
	smpb "github.com/infodancer/maildancer/internal/session-manager/proto/sessionmanager/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// verifyCost is how long the wrong-password path spends "hashing". It stands in
// for argon2id, and it is the asymmetry the uniform deadline has to mask: the
// nonexistent-account path below spends nothing.
const verifyCost = 40 * time.Millisecond

// timingAuthAgent distinguishes the two failure causes and makes them cost
// deliberately different amounts, so a test can tell whether the difference
// leaks into response time.
type timingAuthAgent struct{}

func (timingAuthAgent) Authenticate(_ context.Context, username, password string) (*auth.AuthSession, error) {
	if username != "alice" {
		// Nonexistent account: no password hash to verify. Returns immediately,
		// exactly the asymmetry auth/passwd's decoy verify exists to narrow.
		return nil, autherrors.ErrUserNotFound
	}
	time.Sleep(verifyCost) // stand-in for argon2id
	if password != "correct" {
		return nil, autherrors.ErrAuthFailed
	}
	return &auth.AuthSession{User: &auth.User{Username: "alice", Mailbox: "alice@example.com"}}, nil
}

func (timingAuthAgent) UserExists(_ context.Context, _ string) (bool, error) { return true, nil }

func (timingAuthAgent) ResolveForward(_ context.Context, _ string) ([]string, bool) {
	return nil, false
}

func (timingAuthAgent) Close() error { return nil }

// newTimingServer builds a sessionServer with a real peerfilter over miniredis
// and the given uniform failure delay.
func newTimingServer(t *testing.T, failDelay time.Duration) (*sessionServer, *peerfilter.Filter) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		MaxRetries:  -1,
		DialTimeout: 250 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	filter, err := peerfilter.New(peerfilter.Defaults(), client, nil)
	if err != nil {
		t.Fatalf("peerfilter.New: %v", err)
	}

	provider := &wiringDomainProvider{d: &domain.Domain{
		Name:      "example.com",
		AuthAgent: timingAuthAgent{},
	}}
	router := domain.NewAuthRouter(provider, nil)
	t.Cleanup(func() { _ = router.Close() })

	mgr := manager.New(&config.Config{}, router, provider, nil)
	t.Cleanup(mgr.Close)

	return &sessionServer{mgr: mgr, filter: filter, authFailDelay: failDelay}, filter
}

// timeLogin returns how long one failed Login took.
func timeLogin(t *testing.T, srv *sessionServer, username, password, ip string) time.Duration {
	t.Helper()
	start := time.Now()
	_, err := srv.Login(context.Background(), &smpb.LoginRequest{
		Username: username, Password: password, ClientIp: ip,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an authentication failure")
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("status code = %v, want Unauthenticated", got)
	}
	return elapsed
}

// median is less sensitive than a mean to a single scheduler hiccup, which
// matters for a timing assertion running on shared CI hardware.
func median(samples []time.Duration) time.Duration {
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// sampleBothPaths collects response times for the nonexistent-account and
// wrong-password paths, alternating so that any drift in machine load affects
// both equally. Each sample uses a fresh address, since the first
// nonexistent-account attempt bans the one it came from.
func sampleBothPaths(t *testing.T, srv *sessionServer, n int) (missing, wrongPass []time.Duration) {
	t.Helper()
	for i := range n {
		ip := "203.0.113." + itoa(i+1)
		missing = append(missing, timeLogin(t, srv, "nosuchuser@example.com", "whatever", ip))
		wrongPass = append(wrongPass, timeLogin(t, srv, "alice@example.com", "wrong", ip))
	}
	return missing, wrongPass
}

// TestLogin_FailureTimingIsIndistinguishable is the test #206 asks for
// explicitly. Rule 1 makes the nonexistent-account path behave differently --
// it bans the peer and skips the password verify -- so without a common
// deadline its response time would be an account-existence oracle, and no
// amount of care in the response text would hide that.
//
// It asserts on the distributions, not a single pair: one measurement passes
// trivially and proves nothing.
func TestLogin_FailureTimingIsIndistinguishable(t *testing.T) {
	const failDelay = 300 * time.Millisecond
	srv, _ := newTimingServer(t, failDelay)

	missing, wrongPass := sampleBothPaths(t, srv, 9)

	medMissing, medWrong := median(missing), median(wrongPass)

	// Both paths must be held to the deadline, so both medians sit at or above
	// it -- the nonexistent path cannot come back early.
	for name, med := range map[string]time.Duration{"missing": medMissing, "wrong-password": medWrong} {
		if med < failDelay {
			t.Errorf("%s median = %v, want >= the %v deadline", name, med, failDelay)
		}
	}

	// And they must be close to each other. The tolerance is well under the
	// verify cost being masked: if the asymmetry leaked through, the gap would
	// be about verifyCost, not a fraction of it.
	gap := medMissing - medWrong
	if gap < 0 {
		gap = -gap
	}
	if gap >= verifyCost/2 {
		t.Errorf("median gap = %v (missing=%v wrong=%v); the %v verify asymmetry is observable",
			gap, medMissing, medWrong, verifyCost)
	}

	// No individual sample may finish early either, or a patient attacker could
	// find the fast path by looking at minimums rather than averages.
	for i, d := range missing {
		if d < failDelay {
			t.Errorf("nonexistent-account sample %d returned in %v, before the %v deadline",
				i, d, failDelay)
		}
	}
}

// TestLogin_TimingLeaksWithoutTheDeadline is the control for the test above. It
// asserts the asymmetry IS visible when the deadline is disabled, which is what
// proves the previous test is measuring something real rather than passing
// because the timing signal was never there.
func TestLogin_TimingLeaksWithoutTheDeadline(t *testing.T) {
	srv, _ := newTimingServer(t, 0)

	missing, wrongPass := sampleBothPaths(t, srv, 9)
	medMissing, medWrong := median(missing), median(wrongPass)

	if medMissing >= medWrong {
		t.Fatalf("expected the nonexistent-account path to be faster with no deadline "+
			"(missing=%v wrong=%v)", medMissing, medWrong)
	}
	if gap := medWrong - medMissing; gap < verifyCost/2 {
		t.Errorf("gap = %v with the deadline disabled; the harness is not producing "+
			"a detectable asymmetry, so the indistinguishability test proves nothing", gap)
	}
}

// TestLogin_NonexistentAccountBansOnFirstAttempt is rule 1: one attempt, not a
// threshold. 41 of the 59 addresses in the measured spray made exactly one
// attempt, so any threshold above 1 misses almost all of it.
func TestLogin_NonexistentAccountBansOnFirstAttempt(t *testing.T) {
	srv, filter := newTimingServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.5"

	if v := filter.Check(ctx, ip); v.Banned {
		t.Fatal("precondition: address should not start banned")
	}

	timeLogin(t, srv, "postmaster@example.com", "whatever", ip)

	if v := filter.Check(ctx, ip); !v.Banned {
		t.Error("one attempt against a nonexistent account did not ban the address")
	}
}

// TestLogin_WrongPasswordDoesNotBan keeps rule 1 off the case where a false
// positive locks out a real person: a stale saved password is what this looks
// like, and it is handled by rule 2's graduated counter instead.
func TestLogin_WrongPasswordDoesNotBan(t *testing.T) {
	srv, filter := newTimingServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.5"

	for range 5 {
		timeLogin(t, srv, "alice@example.com", "wrong", ip)
	}

	if v := filter.Check(ctx, ip); v.Banned {
		t.Error("wrong password on a real account produced a connection ban")
	}
}

// TestLogin_BanIsInvisibleInTheResponse pins the other half of the enumeration
// defence: the ban happens server-side, and the client sees the same
// undifferentiated failure either way.
func TestLogin_BanIsInvisibleInTheResponse(t *testing.T) {
	srv, _ := newTimingServer(t, 0)

	_, missingErr := srv.Login(context.Background(), &smpb.LoginRequest{
		Username: "nosuchuser@example.com", Password: "x", ClientIp: "203.0.113.5",
	})
	_, wrongErr := srv.Login(context.Background(), &smpb.LoginRequest{
		Username: "alice@example.com", Password: "wrong", ClientIp: "198.51.100.9",
	})

	if status.Code(missingErr) != status.Code(wrongErr) {
		t.Errorf("status codes differ: missing=%v wrong=%v",
			status.Code(missingErr), status.Code(wrongErr))
	}
	if missingErr.Error() != wrongErr.Error() {
		t.Errorf("messages differ:\n missing = %q\n wrong   = %q",
			missingErr.Error(), wrongErr.Error())
	}
}

// TestLogin_NoClientIPCannotBan covers the degenerate case: with no address
// there is nothing to ban, and it must not error out the login path.
func TestLogin_NoClientIPCannotBan(t *testing.T) {
	srv, filter := newTimingServer(t, 0)

	_, err := srv.Login(context.Background(), &smpb.LoginRequest{
		Username: "nosuchuser@example.com", Password: "x",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status = %v, want Unauthenticated", err)
	}

	bans, lerr := filter.List(context.Background())
	if lerr != nil {
		t.Fatalf("List: %v", lerr)
	}
	if len(bans) != 0 {
		t.Errorf("bans recorded with no client IP: %+v", bans)
	}
}

// TestAwaitFailDeadline_ReturnsOnCancel keeps a hung-up client from pinning the
// goroutine for the whole delay.
func TestAwaitFailDeadline_ReturnsOnCancel(t *testing.T) {
	srv := &sessionServer{authFailDelay: 10 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	srv.awaitFailDeadline(ctx, time.Now())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("awaitFailDeadline held for %v after the context was cancelled", elapsed)
	}
}

// TestAwaitFailDeadline_NoOpWhenPastDeadline documents the case the decoy verify
// exists for: once the work has outlasted the deadline there is nothing left to
// equalize, so the paths must not diverge in cost.
func TestAwaitFailDeadline_NoOpWhenPastDeadline(t *testing.T) {
	srv := &sessionServer{authFailDelay: 10 * time.Millisecond}

	start := time.Now()
	srv.awaitFailDeadline(context.Background(), time.Now().Add(-time.Second))
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Errorf("awaitFailDeadline slept %v for an already-expired deadline", elapsed)
	}
}

func TestAwaitFailDeadline_DisabledWhenZero(t *testing.T) {
	srv := &sessionServer{authFailDelay: 0}

	start := time.Now()
	srv.awaitFailDeadline(context.Background(), time.Now())
	if elapsed := time.Since(start); elapsed > 5*time.Millisecond {
		t.Errorf("awaitFailDeadline slept %v with the delay disabled", elapsed)
	}
}

// itoa avoids importing strconv for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

// TestLogin_KnownGoodSurvivesRule1 is the interaction that makes rule 1 safe to
// ship. Rule 1 bans on a single nonexistent-account attempt, which is what
// catches the measured spray -- but a shared address carrying a real user would
// otherwise be locked out by one hostile connection. The known-good exemption
// suppresses the ban for an address a real user has authenticated from.
//
// The ban is still recorded; only its enforcement is suppressed, so the
// operator can still see what policy decided.
func TestLogin_KnownGoodSurvivesRule1(t *testing.T) {
	srv, filter := newTimingServer(t, 0)
	ctx := context.Background()
	const ip = "203.0.113.5"

	// Establish the address as known-good the only way possible: a real login.
	if err := filter.RecordGood(ctx, ip); err != nil {
		t.Fatalf("RecordGood: %v", err)
	}

	// Now a nonexistent-account attempt from the same address fires rule 1.
	timeLogin(t, srv, "postmaster@example.com", "whatever", ip)

	if v := filter.Check(ctx, ip); v.Banned {
		t.Error("known-good address was banned by rule 1; a real user behind a " +
			"shared address would be locked out")
	}

	// The ban exists on record even though it is not being enforced.
	bans, err := filter.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(bans) != 1 {
		t.Errorf("rule 1 did not record a ban (got %d); suppression should hide "+
			"enforcement, not the decision", len(bans))
	}
}

// TestLogin_UnknownAddressStillBannedByRule1 is the companion: the exemption
// must not weaken rule 1 for addresses with no successful login behind them,
// which is the overwhelming majority of the measured traffic.
func TestLogin_UnknownAddressStillBannedByRule1(t *testing.T) {
	srv, filter := newTimingServer(t, 0)
	ctx := context.Background()
	const ip = "198.51.100.9"

	timeLogin(t, srv, "postmaster@example.com", "whatever", ip)

	if v := filter.Check(ctx, ip); !v.Banned {
		t.Error("address with no successful login was not banned by rule 1")
	}
}
