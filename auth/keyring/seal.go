package keyring

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"

	"github.com/infodancer/maildancer/internal/kdfcost"
)

// SlotType identifies how a wrap-slot unlocks the KEK.
type SlotType string

const (
	SlotDevice     SlotType = "device"     // KEK wrapped to a device public key (SCMP; not built here)
	SlotPassphrase SlotType = "passphrase" // KEK wrapped under a password-derived key
	SlotEscrow     SlotType = "escrow"     // KEK wrapped to a domain recovery public key (disclosed)
)

// kekSize is the KEK length; xNonceSize is the XChaCha20-Poly1305 nonce length.
const (
	kekSize    = 32
	xNonceSize = chacha20poly1305.NonceSizeX // 24
)

// Argon2id parameters for passphrase slots. The cost comes from the shared
// kdfcost.Default profile; it is stored self-describingly in each slot's
// KDFParams (see newKDFParams) so a future cost change -- or the lowered cost a
// test binary sets -- does not strand old blobs: open reads each slot's recorded
// cost, not the current default. Deliberately independent of any auth-path KDF.
// argon2KeyLen and saltSize stay const -- they are format invariants.
const (
	argon2KeyLen = 32
	saltSize     = 32
)

// wrapInfo domain-separates the keyring wrap-key from any other value derivable
// from the same password (notably the auth verifier). HKDF is keyed by the
// argon2id output and expanded under this fixed label.
const wrapInfo = "maildancer/keyring-wrap/v1"

// passphraseSlotID is the canonical id for the single password wrap-slot in the
// v1 (legacy-equivalent) keyring. Multi-device slots use device fingerprints.
const passphraseSlotID = "primary"

// KDFParams records the self-describing argon2id parameters for a passphrase
// slot. nil for non-passphrase slots.
type KDFParams struct {
	Algorithm string `json:"algorithm"` // "argon2id"
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory"`
	Threads   uint8  `json:"threads"`
	KeyLen    uint32 `json:"key_len"`
	Info      string `json:"info"` // HKDF info label (domain separation)
}

// WrapSlot describes one way to unlock the KEK. The server sees the slot table
// (count and type) but no usable key material unless it holds an escrow slot's
// recovery private key.
type WrapSlot struct {
	Type       SlotType   `json:"slot_type"`
	ID         string     `json:"slot_id"`
	WrappedKEK []byte     `json:"wrapped_kek"`
	KDF        *KDFParams `json:"kdf,omitempty"`
}

// Sealed is what the server stores: the opaque keyring blob plus the wrap-slot
// table and a monotonic doc_version for compare-and-swap.
type Sealed struct {
	Version    int        `json:"version"`
	DocVersion uint64     `json:"doc_version"`
	Blob       []byte     `json:"kek_wrapped_blob"` // nonce(24) || ciphertext
	Slots      []WrapSlot `json:"wrap_slots"`
}

// sealAAD binds the format version and doc_version into the keyring seal's
// associated data, so an attacker cannot roll the blob back to an older
// doc_version (or downgrade the format) while keeping the advertised header.
func sealAAD(version int, docVersion uint64) []byte {
	aad := make([]byte, 1+8)
	aad[0] = byte(version)
	binary.BigEndian.PutUint64(aad[1:], docVersion)
	return aad
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	return b, nil
}

// sealKeyring encrypts the keyring document under the KEK with XChaCha20-Poly1305,
// binding version+doc_version as AAD. Output is nonce(24) || ciphertext.
func sealKeyring(k *Keyring, kek []byte, docVersion uint64) ([]byte, error) {
	pt, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("marshal keyring: %w", err)
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	nonce, err := randBytes(xNonceSize)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, pt, sealAAD(formatVersion, docVersion))
	return append(nonce, ct...), nil
}

// openKeyring reverses sealKeyring. A failed authentication (wrong KEK, tampered
// blob, or mismatched version/doc_version AAD) returns ErrKeyDecryptFailed.
func openKeyring(blob, kek []byte, version int, docVersion uint64) (*Keyring, error) {
	if len(blob) < xNonceSize+chacha20poly1305.Overhead {
		return nil, errInvalidFormat
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	nonce := blob[:xNonceSize]
	pt, err := aead.Open(nil, nonce, blob[xNonceSize:], sealAAD(version, docVersion))
	if err != nil {
		return nil, errDecryptFailed
	}
	var k Keyring
	if err := json.Unmarshal(pt, &k); err != nil {
		return nil, errInvalidFormat
	}
	return &k, nil
}

// deriveWrapKey derives a passphrase slot's wrap-key: argon2id(password) keyed
// into HKDF-SHA256 expanded under the domain-separation info label.
func deriveWrapKey(password string, p KDFParams) ([]byte, error) {
	ikm := argon2.IDKey([]byte(password), p.Salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	wk, err := hkdf.Key(sha256.New, ikm, nil, p.Info, kekSize)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return wk, nil
}

// newPassphraseSlot wraps the KEK under a freshly salted password-derived key.
func newPassphraseSlot(kek []byte, password, slotID string) (WrapSlot, error) {
	salt, err := randBytes(saltSize)
	if err != nil {
		return WrapSlot{}, err
	}
	p := KDFParams{
		Algorithm: "argon2id",
		Salt:      salt,
		Time:      kdfcost.Default.Time,
		Memory:    kdfcost.Default.Memory,
		Threads:   kdfcost.Default.Threads,
		KeyLen:    argon2KeyLen,
		Info:      wrapInfo,
	}
	wk, err := deriveWrapKey(password, p)
	if err != nil {
		return WrapSlot{}, err
	}
	wrapped, err := aeadWrap(kek, wk, slotID)
	if err != nil {
		return WrapSlot{}, err
	}
	return WrapSlot{Type: SlotPassphrase, ID: slotID, WrappedKEK: wrapped, KDF: &p}, nil
}

// unwrapPassphrase recovers the KEK from a passphrase slot.
func (s WrapSlot) unwrapPassphrase(password string) ([]byte, error) {
	if s.Type != SlotPassphrase || s.KDF == nil {
		return nil, errInvalidFormat
	}
	wk, err := deriveWrapKey(password, *s.KDF)
	if err != nil {
		return nil, err
	}
	return aeadUnwrap(s.WrappedKEK, wk, s.ID)
}

// aeadWrap seals the KEK under a 32-byte slot key, binding slotID as AAD so a
// wrapped KEK cannot be moved to a different slot. Output is nonce || ciphertext.
func aeadWrap(kek, slotKey []byte, slotID string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(slotKey)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	nonce, err := randBytes(xNonceSize)
	if err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, kek, []byte(slotID))...), nil
}

func aeadUnwrap(wrapped, slotKey []byte, slotID string) ([]byte, error) {
	if len(wrapped) < xNonceSize+chacha20poly1305.Overhead {
		return nil, errInvalidFormat
	}
	aead, err := chacha20poly1305.NewX(slotKey)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	kek, err := aead.Open(nil, wrapped[:xNonceSize], wrapped[xNonceSize:], []byte(slotID))
	if err != nil {
		return nil, errDecryptFailed
	}
	return kek, nil
}

// --- High-level facade ------------------------------------------------------

// Create builds a new keyring holding a single active X25519 encryption entry
// and seals it under a passphrase wrap-slot. pub/priv are raw 32-byte keys.
func Create(pub, priv []byte, password string) ([]byte, error) {
	k := &Keyring{Version: keyringVersion}
	e := Entry{Algorithm: AlgorithmX25519, Purpose: PurposeEncryption, PublicKey: pub, PrivateKey: priv}
	k.normalizeEntry(&e)
	k.Entries = []Entry{e}
	return sealNew(k, password)
}

// sealNew seals a keyring at doc_version 1 under a single passphrase slot.
func sealNew(k *Keyring, password string) ([]byte, error) {
	kek, err := randBytes(kekSize)
	if err != nil {
		return nil, err
	}
	const docVersion = 1
	blob, err := sealKeyring(k, kek, docVersion)
	if err != nil {
		return nil, err
	}
	slot, err := newPassphraseSlot(kek, password, passphraseSlotID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Sealed{Version: formatVersion, DocVersion: docVersion, Blob: blob, Slots: []WrapSlot{slot}})
}

// parse decodes the sealed envelope, rejecting structurally invalid input.
func parse(sealed []byte) (Sealed, error) {
	var s Sealed
	if err := json.Unmarshal(sealed, &s); err != nil {
		return Sealed{}, errInvalidFormat
	}
	if s.Version == 0 || len(s.Blob) == 0 {
		return Sealed{}, errInvalidFormat
	}
	return s, nil
}

// unsealWithPassword opens a sealed keyring via any passphrase slot, returning
// the keyring, the recovered KEK, and the parsed envelope.
func unsealWithPassword(sealed []byte, password string) (*Keyring, []byte, Sealed, error) {
	s, err := parse(sealed)
	if err != nil {
		return nil, nil, Sealed{}, err
	}
	sawSlot := false
	for _, slot := range s.Slots {
		if slot.Type != SlotPassphrase {
			continue
		}
		sawSlot = true
		kek, err := slot.unwrapPassphrase(password)
		if err != nil {
			continue // wrong password for this slot; try the next
		}
		kr, err := openKeyring(s.Blob, kek, s.Version, s.DocVersion)
		if err != nil {
			return nil, nil, Sealed{}, err
		}
		return kr, kek, s, nil
	}
	if !sawSlot {
		return nil, nil, Sealed{}, errInvalidFormat
	}
	return nil, nil, Sealed{}, errDecryptFailed
}

// OpenWithPassword unseals a keyring via its passphrase wrap-slot.
func OpenWithPassword(sealed []byte, password string) (*Keyring, error) {
	kr, _, _, err := unsealWithPassword(sealed, password)
	return kr, err
}

// RekeyPassword re-wraps the KEK under newPassword. It does NOT re-encrypt the
// keyring blob or bump doc_version -- only the passphrase wrap-slot changes, so
// the cost is one argon2 derivation, not a full re-seal. Non-passphrase slots
// (e.g. escrow) are preserved.
func RekeyPassword(sealed []byte, oldPassword, newPassword string) ([]byte, error) {
	_, kek, s, err := unsealWithPassword(sealed, oldPassword)
	if err != nil {
		return nil, err
	}
	slot, err := newPassphraseSlot(kek, newPassword, passphraseSlotID)
	if err != nil {
		return nil, err
	}
	kept := slot.replaceInto(s.Slots)
	s.Slots = kept
	return json.Marshal(s)
}

// replaceInto returns slots with all passphrase slots replaced by the receiver.
func (s WrapSlot) replaceInto(slots []WrapSlot) []WrapSlot {
	out := make([]WrapSlot, 0, len(slots)+1)
	out = append(out, s)
	for _, sl := range slots {
		if sl.Type == SlotPassphrase {
			continue
		}
		out = append(out, sl)
	}
	return out
}

// AddEntry opens the keyring, appends e (without disturbing existing entries),
// re-seals under the same KEK at the next doc_version, and rewraps the passphrase
// slot to that KEK. Used for rotation/archive: historic keys are retained.
func AddEntry(sealed []byte, password string, e Entry) ([]byte, error) {
	kr, kek, s, err := unsealWithPassword(sealed, password)
	if err != nil {
		return nil, err
	}
	kr.normalizeEntry(&e)
	kr.Entries = append(kr.Entries, e)
	return reseal(kr, kek, s)
}

// reseal re-encrypts the keyring under the same KEK at doc_version+1. Slots are
// unchanged (they wrap the KEK, which is unchanged), but the AAD now binds the
// new doc_version so the prior blob cannot be substituted.
func reseal(kr *Keyring, kek []byte, s Sealed) ([]byte, error) {
	s.DocVersion++
	blob, err := sealKeyring(kr, kek, s.DocVersion)
	if err != nil {
		return nil, err
	}
	s.Blob = blob
	return json.Marshal(s)
}

// --- Escrow slot (format only; activation deferred) -------------------------

// AddEscrowSlot adds a domain-recovery escrow wrap-slot. It recovers the KEK via
// the passphrase slot, then wraps it to recoveryPub using a NaCl anonymous
// sealed box. The escrow slot's presence is what would flip the published
// `escrowed` disclosure once escrow mode is activated -- custody of the recovery
// private key and the encryption_mode wiring are a separate, deferred effort.
func AddEscrowSlot(sealed []byte, password string, recoveryPub []byte, domain string) ([]byte, error) {
	_, kek, s, err := unsealWithPassword(sealed, password)
	if err != nil {
		return nil, err
	}
	if len(recoveryPub) != 32 {
		return nil, errInvalidFormat
	}
	var pub [32]byte
	copy(pub[:], recoveryPub)
	wrapped, err := box.SealAnonymous(nil, kek, &pub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("seal escrow: %w", err)
	}
	// Replace any existing escrow slot for this domain, keep all others.
	out := make([]WrapSlot, 0, len(s.Slots)+1)
	for _, sl := range s.Slots {
		if sl.Type == SlotEscrow && sl.ID == domain {
			continue
		}
		out = append(out, sl)
	}
	out = append(out, WrapSlot{Type: SlotEscrow, ID: domain, WrappedKEK: wrapped})
	s.Slots = out
	return json.Marshal(s)
}

// OpenWithEscrow recovers a keyring using the domain recovery keypair. This is
// the server-side recovery path; its mere availability is why an escrow slot
// must be disclosed.
func OpenWithEscrow(sealed []byte, recoveryPub, recoveryPriv []byte) (*Keyring, error) {
	s, err := parse(sealed)
	if err != nil {
		return nil, err
	}
	if len(recoveryPub) != 32 || len(recoveryPriv) != 32 {
		return nil, errInvalidFormat
	}
	var pub, priv [32]byte
	copy(pub[:], recoveryPub)
	copy(priv[:], recoveryPriv)
	for _, sl := range s.Slots {
		if sl.Type != SlotEscrow {
			continue
		}
		kek, ok := box.OpenAnonymous(nil, sl.WrappedKEK, &pub, &priv)
		if !ok {
			continue
		}
		return openKeyring(s.Blob, kek, s.Version, s.DocVersion)
	}
	return nil, errDecryptFailed
}
