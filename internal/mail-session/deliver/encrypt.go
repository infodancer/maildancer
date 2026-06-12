package deliver

import (
	"context"
	"log/slog"

	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/msgstore"
)

// maybeEncrypt applies at-rest encryption when the request carries an
// encryption key hint. It runs after Sieve evaluation (which needs plaintext)
// and before any write, so every delivery path -- inbox keep, Sieve fileinto,
// redirect :copy -- writes the same encrypted blob. This is the seam coverage
// required by issue #53: encrypting here, rather than inside a DeliveryAgent
// wrapper, makes bypassing the seam structurally impossible.
//
// Returns the bytes to write and the encryption metadata for the envelope.
// With no hint, the message passes through unchanged (encryption is
// request-driven; smtpd does not set the hint yet).
//
// Fail-closed: when encryption is requested but cannot be performed (no key
// provider, no key on file, encryption failure), the delivery is temp-failed
// rather than ever falling back to a plaintext write. A missing key under an
// explicit encryption request is a configuration error the admin must fix;
// the sending MTA holds and retries meanwhile.
func (dlvr *Deliverer) maybeEncrypt(ctx context.Context, dom *domain.Domain, req DeliverRequest, msg []byte) ([]byte, *msgstore.EncryptionInfo, *DeliverResponse) {
	if req.EncryptionKeyHint == "" {
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

	kp, ok := dom.AuthAgent.(auth.KeyProvider)
	if !ok {
		return failClosed("encryption requested but domain auth agent provides no keys", nil)
	}

	// The key hint requests encryption; the key itself is looked up by the
	// recipient's base localpart, matching the KeyProvider contract used
	// elsewhere (key backend files are per-username).
	localpart, _ := splitAddress(msgstore.ParseRecipient(req.Recipient).Address)
	pubKey, err := kp.GetPublicKey(ctx, localpart)
	if err != nil {
		return failClosed("encryption requested but no public key for recipient", err)
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
