package domain

// TestMailDeliveryAgent_LocalForwardSecondHop and
// TestMailDeliveryAgent_Forwarded_NoSecondHop together document and verify
// the 1-hop forwarding contract.
//
// Background: MailDeliveryAgent.Deliver re-resolves forwarding rules via the
// forwardChain on every call.  Before the fix, it had no "already forwarded"
// guard.  When deliver.go set req.Forwarded=true (skipping its own
// ResolveForward gate) and then called dom.DeliveryAgent.Deliver, a locally-
// served forward target would be forwarded a second time.
//
// Fix: msgstore.Envelope gains a Forwarded bool.  deliver.go stage 4 sets
// envelope.Forwarded = req.Forwarded.  MailDeliveryAgent skips rule resolution
// when envelope.Forwarded is true.  The recursive call sets Forwarded=true on
// the forwarded envelope so the target domain's agent also stops.
//
// These tests use only package-internal stubs (no deliver.go, no unmerged
// plan-003 fixtures) because the mechanism under test is MailDeliveryAgent
// alone.

import (
	"bytes"
	"context"
	"testing"

	"github.com/infodancer/maildancer/auth/forwards"
	"github.com/infodancer/maildancer/msgstore"
)

// TestMailDeliveryAgent_LocalForwardSecondHop verifies that when a message
// arrives already marked Forwarded=true, MailDeliveryAgent delivers it locally
// without re-resolving the forward rule.
//
// alice@example.com has a forward rule to bob@example.com.  Calling
// aliceDelivery.Deliver with envelope.Forwarded=true must NOT deliver to bob.
// Instead it must deliver locally (to aliceInner).
func TestMailDeliveryAgent_LocalForwardSecondHop(t *testing.T) {
	// bobInner is the local delivery sink for bob@example.com.
	bobInner := &stubDeliveryAgent{}

	// bob@example.com has no forward rule -- local delivery only.
	bobChain := &forwardChain{
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}

	bobDomain := &Domain{Name: "example.com"}

	provider := &stubDomainProvider{
		domains: map[string]*Domain{"example.com": bobDomain},
	}

	bobDelivery := &MailDeliveryAgent{inner: bobInner, chain: bobChain, provider: provider}
	bobDomain.DeliveryAgent = bobDelivery

	// alice@example.com has a forward rule: alice -> bob@example.com.
	aliceFwdMap := forwards.FromMap(map[string]string{"alice": "bob@example.com"})
	aliceChain := &forwardChain{
		domainForwards:  aliceFwdMap,
		defaultForwards: &forwards.ForwardMap{},
	}
	aliceInner := &stubDeliveryAgent{}
	aliceDelivery := &MailDeliveryAgent{inner: aliceInner, chain: aliceChain, provider: provider}

	// Deliver with Forwarded=true -- simulates deliver.go stage 4 when
	// req.Forwarded was true and the ResolveForward gate was already skipped.
	env := msgstore.Envelope{
		Recipients: []string{"alice@example.com"},
		Forwarded:  true,
	}
	if err := aliceDelivery.Deliver(context.Background(), env, bytes.NewReader([]byte("test"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With the fix: forward rule must NOT be followed.
	if len(bobInner.delivered) != 0 {
		t.Errorf("second hop: expected 0 deliveries to bob, got %d", len(bobInner.delivered))
	}
	// Message must land in alice's local store.
	if len(aliceInner.delivered) != 1 {
		t.Errorf("local delivery: expected 1 delivery to aliceInner, got %d", len(aliceInner.delivered))
	}
}

// TestMailDeliveryAgent_ForwardedFlagPropagated verifies that when a message
// is not yet forwarded, MailDeliveryAgent follows the rule to the target and
// sets Forwarded=true on the forwarded envelope -- so that the target domain's
// MailDeliveryAgent does not forward again (the recursive-hop case).
func TestMailDeliveryAgent_ForwardedFlagPropagated(t *testing.T) {
	// bobInner is the local delivery sink.  We inspect the envelopes it receives.
	bobInner := &stubDeliveryAgent{}

	bobChain := &forwardChain{
		domainForwards:  &forwards.ForwardMap{},
		defaultForwards: &forwards.ForwardMap{},
	}
	bobDomain := &Domain{Name: "example.com"}

	provider := &stubDomainProvider{
		domains: map[string]*Domain{"example.com": bobDomain},
	}

	bobDelivery := &MailDeliveryAgent{inner: bobInner, chain: bobChain, provider: provider}
	bobDomain.DeliveryAgent = bobDelivery

	aliceFwdMap := forwards.FromMap(map[string]string{"alice": "bob@example.com"})
	aliceChain := &forwardChain{
		domainForwards:  aliceFwdMap,
		defaultForwards: &forwards.ForwardMap{},
	}
	aliceInner := &stubDeliveryAgent{}
	aliceDelivery := &MailDeliveryAgent{inner: aliceInner, chain: aliceChain, provider: provider}

	// Deliver with Forwarded=false (normal first delivery).
	env := msgstore.Envelope{
		Recipients: []string{"alice@example.com"},
		Forwarded:  false,
	}
	if err := aliceDelivery.Deliver(context.Background(), env, bytes.NewReader([]byte("test"))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Forward rule was followed -- bob should have received it.
	if len(bobInner.delivered) != 1 {
		t.Fatalf("expected 1 delivery to bob, got %d", len(bobInner.delivered))
	}

	// The envelope reaching bob must have Forwarded=true so bob's agent
	// would not re-forward (even if bob had a forward rule).
	if !bobInner.delivered[0].Forwarded {
		t.Errorf("forwarded envelope must have Forwarded=true; got false")
	}

	// alice's local store should not have received a copy (it was forwarded).
	if len(aliceInner.delivered) != 0 {
		t.Errorf("expected 0 local deliveries to alice, got %d", len(aliceInner.delivered))
	}
}
