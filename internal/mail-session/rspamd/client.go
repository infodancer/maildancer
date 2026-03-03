// Package rspamd provides a minimal client for the rspamd HTTP controller API.
// It is used by mail-session to submit ham/spam learning signals when messages
// are moved to or from the Junk folder.
package rspamd

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client submits learning requests to an rspamd controller.
type Client struct {
	controller string
	http       *http.Client
}

// New returns a Client that talks to the rspamd controller at the given URL
// (e.g. "http://rspamd:11334").
func New(controller string) *Client {
	return &Client{
		controller: controller,
		http:       &http.Client{Timeout: 10 * time.Second},
	}
}

// LearnSpam submits msg to rspamd as a spam example for user.
// user should be the full address (user@domain) for per-user Bayes corpora.
// Returns nil on success; errors are logged by the caller and never block the
// IMAP operation.
func (c *Client) LearnSpam(ctx context.Context, user string, msg []byte) error {
	return c.learn(ctx, "/learnspam", user, msg)
}

// LearnHam submits msg to rspamd as a ham example for user.
func (c *Client) LearnHam(ctx context.Context, user string, msg []byte) error {
	return c.learn(ctx, "/learnham", user, msg)
}

func (c *Client) learn(ctx context.Context, endpoint, user string, msg []byte) error {
	url := c.controller + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if user != "" {
		req.Header.Set("User", user)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rspamd %s returned %s", endpoint, resp.Status)
	}
	return nil
}
