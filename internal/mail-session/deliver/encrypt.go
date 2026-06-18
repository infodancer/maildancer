package deliver

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/msgstore"
)

// keyringPubFile is the recipient's public-key file inside their user-store
// directory. It matches the layout auth/passwd and internal/admin use:
// {StoreBasePath}/{localpart}/keyring.pub (maildancer#82, maildancer#86).
const keyringPubFile = "keyring.pub"

// maybeEncrypt applies at-rest encryption when the recipient has an encryption
// key on file. It runs after Sieve evaluation (which needs plaintext) and
// before any write, so every delivery path -- inbox keep, Sieve fileinto,
// redirect :copy -- writes the same encrypted blob. Encrypting here, rather
// than inside a DeliveryAgent wrapper, makes bypassing the seam structurally
// impossible (issue #53).
//
// The recipient public key is read directly from the recipient's own user-store
// directory ({StoreBasePath}/{localpart}/keyring.pub). This is the data tree the
// recipient owns and the delivery process -- running as the recipient uid -- can
// read. The key is deliberately NOT resolved through the domain provider /
// auth agent: that path reads the config tree (config.toml, passwd), which the
// recipient uid cannot access, so it returned "no key" and silently delivered
// plaintext (maildancer#86).
//
// The gate is recipient key presence (issue #65): a recipient with a keyring
// gets encrypted mail; one without gets plaintext. Per-domain "encryption mode"
// governs whether new users are provisioned a key -- not this runtime decision.
//
// Fail-closed: when the keyring is present but cannot be read or used (read
// error other than not-exist, encryption failure), the delivery is temp-failed
// rather than ever falling back to a plaintext write. A recipient with no
// keyring is not an error -- that is the unencrypted case.
func (dlvr *Deliverer) maybeEncrypt(ctx context.Context, dom *domain.Domain, req DeliverRequest, msg []byte) ([]byte, *msgstore.EncryptionInfo, *DeliverResponse) {
	_ = ctx
	_ = dom

	failClosed := func(logMsg string, err error) ([]byte, *msgstore.EncryptionInfo, *DeliverResponse) {
		attrs := []any{slog.String("msgid", req.MsgID), slog.String("recipient", req.Recipient)}
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

	if dlvr.cfg.StoreBasePath == "" {
		// No store base configured: at-rest encryption is not available here.
		// Plaintext, not an error.
		return msg, nil, nil
	}

	// The keyring is keyed by the recipient's base localpart, beside the maildir.
	localpart, _ := splitAddress(msgstore.ParseRecipient(req.Recipient).Address)
	keyringPath := filepath.Join(dlvr.cfg.StoreBasePath, localpart, keyringPubFile)

	pubKey, err := os.ReadFile(keyringPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No keyring on file: the recipient is not an encryption user.
			// Deliver plaintext. This is the gate, not a failure.
			return msg, nil, nil
		}
		// Present-but-unreadable (or any other read error) for a recipient who
		// may well have a key: fail closed rather than risk a plaintext write.
		return failClosed("reading recipient keyring for at-rest encryption", err)
	}

	encrypted, err := msgstore.EncryptMessage(msg, pubKey)
	if err != nil {
		return failClosed("encrypting message for delivery", err)
	}

	slog.Debug("message encrypted for at-rest storage",
		slog.String("msgid", req.MsgID),
		slog.String("recipient", req.Recipient),
		slog.Int("plaintext_bytes", len(msg)),
		slog.Int("encrypted_bytes", len(encrypted)))
	return encrypted, &msgstore.EncryptionInfo{
		Algorithm: msgstore.EncryptionAlgorithm,
		Encrypted: true,
	}, nil
}
