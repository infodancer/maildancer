package pop3

import (
	"encoding/base64"

	"github.com/emersion/go-sasl"
)

// SupportedSASLMechanisms returns the list of supported SASL mechanisms.
func SupportedSASLMechanisms() []string {
	return []string{sasl.Plain}
}

// DecodeSASLResponse decodes a base64-encoded SASL response.
func DecodeSASLResponse(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// EncodeSASLChallenge encodes a SASL challenge to base64.
func EncodeSASLChallenge(challenge []byte) string {
	return base64.StdEncoding.EncodeToString(challenge)
}
