package passwd

import (
	"github.com/infodancer/maildancer/auth"
	"github.com/infodancer/maildancer/auth/errors"
)

func init() {
	auth.RegisterAuthAgent("passwd", func(config auth.AuthAgentConfig) (auth.AuthenticationAgent, error) {
		if config.CredentialBackend == "" {
			return nil, errors.ErrAuthAgentConfigInvalid
		}
		// KeyBackend is the legacy flat key dir (read-fallback). Per-user
		// keyrings live under UserKeyringBase (the data-tree user-dir parent).
		keyDir := config.KeyBackend
		if keyDir == "" {
			return nil, errors.ErrAuthAgentConfigInvalid
		}
		agent, err := NewAgent(config.CredentialBackend, keyDir)
		if err != nil {
			return nil, err
		}
		return agent.WithUserKeyringBase(config.UserKeyringBase), nil
	})
}
