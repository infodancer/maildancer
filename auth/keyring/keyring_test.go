package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"golang.org/x/crypto/nacl/box"

	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/internal/kdfcost"
)

// TestMain lowers the argon2id passphrase-slot cost to the cheapest valid
// profile for this test binary. Slots store their cost self-describingly, so
// blobs sealed here open here; nothing exercises KDF strength. Full cost under
// -race made auth/keyring slow enough to flake on loaded CI runners (issue #114).
func TestMain(m *testing.M) {
	kdfcost.Default = kdfcost.Params{Time: 1, Memory: 8, Threads: 1}
	os.Exit(m.Run())
}

// newKeypair returns a fresh X25519 keypair as raw 32-byte slices.
func newKeypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p[:], s[:]
}

func TestCreateOpen_RoundTrip(t *testing.T) {
	pub, priv := newKeypair(t)

	sealed, err := Create(pub, priv, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	kr, err := OpenWithPassword(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatalf("OpenWithPassword: %v", err)
	}

	e, ok := kr.ActiveEncryptionKey()
	if !ok {
		t.Fatal("no active encryption key after round-trip")
	}
	if !bytes.Equal(e.PrivateKey, priv) {
		t.Error("round-tripped private key does not match original")
	}
	if !bytes.Equal(e.PublicKey, pub) {
		t.Error("round-tripped public key does not match original")
	}
	if e.Algorithm != AlgorithmX25519 || e.Purpose != PurposeEncryption || e.Status != StatusActive {
		t.Errorf("unexpected entry metadata: %+v", e)
	}
}

func TestCreate_DistinctPerCall(t *testing.T) {
	pub, priv := newKeypair(t)
	a, err := Create(pub, priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(pub, priv, "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Fresh KEK, salt, and nonces per call: identical inputs must never
	// produce identical sealed blobs.
	if bytes.Equal(a, b) {
		t.Error("two Create calls produced identical sealed bytes")
	}
}

func TestOpen_WrongPassword(t *testing.T) {
	pub, priv := newKeypair(t)
	sealed, err := Create(pub, priv, "right")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenWithPassword(sealed, "wrong")
	if !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("wrong password: err = %v, want ErrKeyDecryptFailed", err)
	}
}

func TestOpen_Garbage(t *testing.T) {
	_, err := OpenWithPassword([]byte("not json"), "pw")
	if !errors.Is(err, autherrors.ErrInvalidKeyFormat) {
		t.Errorf("garbage blob: err = %v, want ErrInvalidKeyFormat", err)
	}
}

// TestOpen_DocVersionRollback verifies the AAD binds doc_version: an attacker
// who edits the advertised doc_version (e.g. to roll a blob back) cannot open
// it, because the AAD no longer matches what was sealed.
func TestOpen_DocVersionRollback(t *testing.T) {
	pub, priv := newKeypair(t)
	sealed, err := Create(pub, priv, "pw")
	if err != nil {
		t.Fatal(err)
	}

	var s Sealed
	if err := json.Unmarshal(sealed, &s); err != nil {
		t.Fatal(err)
	}
	s.DocVersion += 1 // tamper without re-sealing the blob
	tampered, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	_, err = OpenWithPassword(tampered, "pw")
	if !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("doc_version rollback: err = %v, want ErrKeyDecryptFailed", err)
	}
}

// TestOpen_VersionDowngrade verifies the AAD binds the format version too.
func TestOpen_VersionDowngrade(t *testing.T) {
	pub, priv := newKeypair(t)
	sealed, err := Create(pub, priv, "pw")
	if err != nil {
		t.Fatal(err)
	}

	var s Sealed
	if err := json.Unmarshal(sealed, &s); err != nil {
		t.Fatal(err)
	}
	s.Version += 1
	tampered, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	_, err = OpenWithPassword(tampered, "pw")
	if !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("version downgrade: err = %v, want ErrKeyDecryptFailed", err)
	}
}

func TestRekeyPassword(t *testing.T) {
	pub, priv := newKeypair(t)
	sealed, err := Create(pub, priv, "old")
	if err != nil {
		t.Fatal(err)
	}

	rekeyed, err := RekeyPassword(sealed, "old", "new")
	if err != nil {
		t.Fatalf("RekeyPassword: %v", err)
	}

	// Old password no longer opens it.
	if _, err := OpenWithPassword(rekeyed, "old"); !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("old password after rekey: err = %v, want ErrKeyDecryptFailed", err)
	}

	// New password opens it and yields the same private key (the keyring
	// blob and KEK are unchanged -- only the wrap-slot was re-derived).
	kr, err := OpenWithPassword(rekeyed, "new")
	if err != nil {
		t.Fatalf("OpenWithPassword(new): %v", err)
	}
	e, ok := kr.ActiveEncryptionKey()
	if !ok || !bytes.Equal(e.PrivateKey, priv) {
		t.Error("rekeyed keyring did not preserve the private key")
	}

	// The encrypted keyring blob itself must be byte-identical -- rekey
	// rewraps the KEK, it does not re-seal the keyring.
	var before, after Sealed
	if err := json.Unmarshal(sealed, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rekeyed, &after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Blob, after.Blob) {
		t.Error("RekeyPassword re-sealed the keyring blob; it should only rewrap the KEK")
	}
	if before.DocVersion != after.DocVersion {
		t.Error("RekeyPassword changed doc_version; it should not")
	}
}

func TestAddEntry_MultiEntry(t *testing.T) {
	pub1, priv1 := newKeypair(t)
	sealed, err := Create(pub1, priv1, "pw")
	if err != nil {
		t.Fatal(err)
	}

	pub2, priv2 := newKeypair(t)
	updated, err := AddEntry(sealed, "pw", Entry{
		Algorithm:  AlgorithmX25519,
		Purpose:    PurposeEncryption,
		PublicKey:  pub2,
		PrivateKey: priv2,
		Status:     StatusActive,
	})
	if err != nil {
		t.Fatalf("AddEntry: %v", err)
	}

	kr, err := OpenWithPassword(updated, "pw")
	if err != nil {
		t.Fatalf("OpenWithPassword: %v", err)
	}
	if len(kr.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(kr.Entries))
	}

	// Both historic private keys must remain retrievable (old mail was
	// encrypted to the prior key).
	var found1, found2 bool
	for _, e := range kr.Entries {
		if bytes.Equal(e.PrivateKey, priv1) {
			found1 = true
		}
		if bytes.Equal(e.PrivateKey, priv2) {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Error("AddEntry lost a historic private key")
	}

	// doc_version must advance so the server can reject a rollback.
	var before, after Sealed
	_ = json.Unmarshal(sealed, &before)
	_ = json.Unmarshal(updated, &after)
	if after.DocVersion <= before.DocVersion {
		t.Errorf("doc_version did not advance: before=%d after=%d", before.DocVersion, after.DocVersion)
	}
}

// TestRotateActiveEntry verifies that marking the prior active key rotated and
// appending a new active key yields exactly one active encryption entry.
func TestSetActiveEncryptionKey(t *testing.T) {
	pub1, priv1 := newKeypair(t)
	kr := &Keyring{
		Version: keyringVersion,
		Entries: []Entry{{Algorithm: AlgorithmX25519, Purpose: PurposeEncryption, PublicKey: pub1, PrivateKey: priv1, Status: StatusActive}},
	}
	pub2, priv2 := newKeypair(t)
	kr.RotateEncryptionKey(Entry{Algorithm: AlgorithmX25519, Purpose: PurposeEncryption, PublicKey: pub2, PrivateKey: priv2})

	active := 0
	for _, e := range kr.Entries {
		if e.Purpose == PurposeEncryption && e.Status == StatusActive {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active encryption entries = %d, want 1", active)
	}
	e, ok := kr.ActiveEncryptionKey()
	if !ok || !bytes.Equal(e.PrivateKey, priv2) {
		t.Error("active key is not the rotated-in key")
	}
}

// TestEscrowSlot_RoundTrip exercises the escrow wrap-slot format end to end at
// the crypto layer: add an escrow slot wrapped to a domain recovery public key,
// then recover the keyring with the recovery private key. Activation (mode,
// custody, disclosure) is deferred; this only proves the format works.
func TestEscrowSlot_RoundTrip(t *testing.T) {
	pub, priv := newKeypair(t)
	sealed, err := Create(pub, priv, "pw")
	if err != nil {
		t.Fatal(err)
	}

	recPub, recPriv := newKeypair(t)
	withEscrow, err := AddEscrowSlot(sealed, "pw", recPub, "example.com")
	if err != nil {
		t.Fatalf("AddEscrowSlot: %v", err)
	}

	// Escrow slot is present and visible in the (opaque-to-server) shape.
	var s Sealed
	if err := json.Unmarshal(withEscrow, &s); err != nil {
		t.Fatal(err)
	}
	var escrowSlots int
	for _, sl := range s.Slots {
		if sl.Type == SlotEscrow {
			escrowSlots++
		}
	}
	if escrowSlots != 1 {
		t.Fatalf("escrow slots = %d, want 1", escrowSlots)
	}

	// The passphrase slot still works after adding escrow.
	if _, err := OpenWithPassword(withEscrow, "pw"); err != nil {
		t.Errorf("passphrase open after AddEscrowSlot: %v", err)
	}

	// Recover via the domain recovery keypair.
	kr, err := OpenWithEscrow(withEscrow, recPub, recPriv)
	if err != nil {
		t.Fatalf("OpenWithEscrow: %v", err)
	}
	e, ok := kr.ActiveEncryptionKey()
	if !ok || !bytes.Equal(e.PrivateKey, priv) {
		t.Error("escrow recovery did not yield the original private key")
	}

	// A wrong recovery key cannot open the escrow slot.
	wrongPub, wrongPriv := newKeypair(t)
	if _, err := OpenWithEscrow(withEscrow, wrongPub, wrongPriv); !errors.Is(err, autherrors.ErrKeyDecryptFailed) {
		t.Errorf("wrong recovery key: err = %v, want ErrKeyDecryptFailed", err)
	}
}

// TestNoActiveKey verifies the accessor signals an empty/exhausted keyring.
func TestNoActiveKey(t *testing.T) {
	kr := &Keyring{Version: keyringVersion}
	if _, ok := kr.ActiveEncryptionKey(); ok {
		t.Error("empty keyring reported an active key")
	}
}
