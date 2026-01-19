package passwd

import (
	"github.com/infodancer/maildancer/msgstore"
	"github.com/infodancer/maildancer/msgstore/errors"
)

func init() {
	msgstore.RegisterAuthAgent("passwd", func(config msgstore.AuthAgentConfig) (msgstore.AuthenticationAgent, error) {
		if config.CredentialBackend == "" {
			return nil, errors.ErrAuthAgentConfigInvalid
		}
		// KeyBackend defaults to same directory as credential file
		keyDir := config.KeyBackend
		if keyDir == "" {
			return nil, errors.ErrAuthAgentConfigInvalid
		}
		return NewAgent(config.CredentialBackend, keyDir)
	})
}
