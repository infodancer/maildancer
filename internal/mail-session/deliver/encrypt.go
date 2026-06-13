package deliver

import (
	"context"
	"errors"
	"log/slog"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	autherrors "github.com/infodancer/maildancer/auth/errors"
	"github.com/infodancer/maildancer/msgstore"
)

// maybeEncrypt applies at-rest encryption when the recipient has an encryption
// key on file. It runs after Sieve evaluation (which needs plaintext) and
// before any write, so every delivery path -- inbox keep, Sieve fileinto,
// redirect :copy -- writes the same encrypted blob. This is the seam coverage
// required by issue #53: encrypting here, rather than inside a DeliveryAgent
// wrapper, makes bypassing the seam structurally impossible.
//
// The gate is recipient key presence (issue #65): a recipient whose domain has
// provisioned them a public key gets encrypted mail; one without a key gets
// plaintext. Per-domain "encryption mode" governs whether new users are
// provisioned a key at all -- not this runtime decision -- so a user with
// existing encrypted mail keeps getting encryption regardless of any later
// domain-policy change.
//
// Returns the bytes to write and the encryption metadata for the envelope.
//
// Fail-closed: when the recipient HAS a key but encryption cannot be performed
// (key backend read error, corrupt key, encryption failure), the delivery is
// temp-failed rather than ever falling back to a plaintext write. A recipient
// with no key is not an error -- that is the unencrypted case.
func (dlvr *Deliverer) maybeEncrypt(ctx context.Context, dom *domain.Domain, req DeliverRequest, msg []byte) ([]byte, *msgstore.EncryptionInfo, *DeliverResponse) {
	kp, ok := dom.AuthAgent.(auth.KeyProvider)
	if !ok {
		// Domain provides no key backend at all: at-rest encryption is not
		// available here. Plaintext, not an error.
		return msg, nil, nil
	}

	failClosed := func(logMsg string, err error) ([]byte, *msgstore.EncryptionInfo, *DeliverResponse) {
		attrs := []any{slog.String("recipient", req.Recipient)}
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		slog.Error(logMsg, attrs...)
		return nil, nil, &DeliverResponse{
			Result:    ResultRejected,
			Temporary: true,
			// Generic reason: the detail is in the server log, not leaked to
			// the sending MTA.
			Reason: "encryption required but not available for recipient",
		}
	}

	// The key is looked up by the recipient's base localpart, matching the
	// KeyProvider contract used elsewhere (key backend files are per-username).
	localpart, _ := splitAddress(msgstore.ParseRecipient(req.Recipient).Address)
	pubKey, err := kp.GetPublicKey(ctx, localpart)
	if err != nil {
		if errors.Is(err, autherrors.ErrKeyNotFound) || errors.Is(err, autherrors.ErrUserNotFound) {
			// No key on file: the recipient is not an encryption user.
			// Deliver plaintext. This is the gate, not a failure.
			return msg, nil, nil
		}
		// A key backend read failure for a recipient who may well have a key:
		// fail closed rather than risk a silent plaintext write.
		return failClosed("reading recipient public key for at-rest encryption", err)
	}

	encrypted, err := msgstore.EncryptMessage(msg, pubKey)
	if err != nil {
		return failClosed("encrypting message for delivery", err)
	}

	slog.Debug("message encrypted for at-rest storage",
		slog.String("recipient", req.Recipient),
		slog.Int("plaintext_bytes", len(msg)),
		slog.Int("encrypted_bytes", len(encrypted)))
	return encrypted, &msgstore.EncryptionInfo{
		Algorithm: msgstore.EncryptionAlgorithm,
		Encrypted: true,
	}, nil
}
