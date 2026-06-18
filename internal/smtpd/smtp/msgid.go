package smtp

import (
	"crypto/rand"
	"encoding/hex"
)

// newMsgID mints a message correlation id: 16 cryptographically-random bytes,
// hex-encoded. It is minted once when a message is accepted at ingress and
// threaded through every delivery stage (local delivery, forward, remote
// enqueue) so the message is traceable by a single id -- no content -- in the
// logs.
//
// The 16 random bytes are compatible with the next-gen protocol message_id
// (bytes, cryptographically random, server-generated, not sender-chosen): the
// same value can serve as the RFC5322 Message-ID and, later, the SCMP/SDMP
// message_id. It is deliberately NOT derived from the inbound Message-ID
// header, which is sender-chosen.
func newMsgID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
