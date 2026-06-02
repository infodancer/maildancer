package domain

import (
	"context"
	"fmt"
	"sync"

	"github.com/infodancer/maildancer/auth"
	autherrors "github.com/infodancer/maildancer/auth/errors"
)

// lazyAuthAgent defers auth.OpenAuthAgent() until the first auth-related method
// call. This allows FilesystemDomainProvider to create Domain objects without
// requiring read access to credential files (e.g., passwd), which is essential
// for privilege-dropped processes that only need domain metadata (forwarding
// rules, spam config, message size limits) and never authenticate users.
type lazyAuthAgent struct {
	cfg   auth.AuthAgentConfig
	once  sync.Once
	agent auth.AuthenticationAgent
	err   error
}

// Compile-time check: lazyAuthAgent must satisfy AuthenticationAgent and KeyProvider.
var (
	_ auth.AuthenticationAgent = (*lazyAuthAgent)(nil)
	_ auth.KeyProvider         = (*lazyAuthAgent)(nil)
)

func (l *lazyAuthAgent) init() {
	l.once.Do(func() {
		l.agent, l.err = auth.OpenAuthAgent(l.cfg)
	})
}

func (l *lazyAuthAgent) Authenticate(ctx context.Context, username, password string) (*auth.AuthSession, error) {
	l.init()
	if l.err != nil {
		return nil, fmt.Errorf("auth agent init: %w", l.err)
	}
	return l.agent.Authenticate(ctx, username, password)
}

func (l *lazyAuthAgent) UserExists(ctx context.Context, username string) (bool, error) {
	l.init()
	if l.err != nil {
		return false, fmt.Errorf("auth agent init: %w", l.err)
	}
	return l.agent.UserExists(ctx, username)
}

func (l *lazyAuthAgent) GetPublicKey(ctx context.Context, username string) ([]byte, error) {
	l.init()
	if l.err != nil {
		return nil, autherrors.ErrKeyNotFound
	}
	if kp, ok := l.agent.(auth.KeyProvider); ok {
		return kp.GetPublicKey(ctx, username)
	}
	return nil, autherrors.ErrKeyNotFound
}

func (l *lazyAuthAgent) HasEncryption(ctx context.Context, username string) (bool, error) {
	l.init()
	if l.err != nil {
		return false, nil
	}
	if kp, ok := l.agent.(auth.KeyProvider); ok {
		return kp.HasEncryption(ctx, username)
	}
	return false, nil
}

func (l *lazyAuthAgent) Close() error {
	// Only close if init() was called and succeeded.
	if l.agent != nil {
		return l.agent.Close()
	}
	return nil
}
