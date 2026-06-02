package queue

import (
	"bytes"
	"crypto"
	"io"

	"github.com/emersion/go-msgauth/dkim"
)

// DKIMKey holds the signing key and selector for a domain.
type DKIMKey struct {
	Selector string
	Key      crypto.Signer
}

// SignDKIM signs a message with the given domain's DKIM key, returning a
// reader over the signed message (DKIM-Signature header prepended to the
// original message).
func SignDKIM(domain, selector string, key crypto.Signer, msg io.Reader) (io.Reader, error) {
	opts := &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   key,
		HeaderKeys: []string{
			"From", "To", "Subject", "Date",
			"Message-ID", "MIME-Version", "Content-Type",
		},
	}

	var buf bytes.Buffer
	if err := dkim.Sign(&buf, msg, opts); err != nil {
		return nil, err
	}
	return &buf, nil
}

// NewDKIMSigner returns a DKIMSign function that looks up signing keys from
// a static map. If no key is found for a domain, the message is returned
// unsigned.
func NewDKIMSigner(keys map[string]DKIMKey) func(string, io.Reader) (io.Reader, error) {
	if len(keys) == 0 {
		return nil
	}
	return func(senderDomain string, msg io.Reader) (io.Reader, error) {
		dk, ok := keys[senderDomain]
		if !ok {
			return msg, nil
		}
		return SignDKIM(senderDomain, dk.Selector, dk.Key, msg)
	}
}
