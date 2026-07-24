package pop3

import (
	"log/slog"

	"github.com/infodancer/maildancer/internal/pop3d/config"
	"github.com/infodancer/maildancer/internal/smclient"
)

// SessionManagerClient is the shared session-manager client (issue #179:
// one client, one recovery engine, no per-daemon copies).
type SessionManagerClient = smclient.Client

// NewSessionManagerClient connects to the session-manager and returns a client.
// Exactly one of cfg.Socket or cfg.Address must be set.
func NewSessionManagerClient(cfg config.SessionManagerConfig, logger *slog.Logger) (*SessionManagerClient, error) {
	return smclient.New(smclient.Config{
		Socket:     cfg.Socket,
		Address:    cfg.Address,
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	}, logger)
}
