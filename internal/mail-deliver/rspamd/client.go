// Package rspamd provides an rspamd HTTP client for spam checking.
package rspamd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Result holds the outcome of a spam check.
type Result struct {
	// Score is the rspamd composite spam score.
	Score float64

	// Action is rspamd's recommended action (e.g. "reject", "soft reject", "no action").
	Action string

	// IsSpam is true when rspamd classifies the message as spam.
	IsSpam bool
}

// Client is a minimal rspamd HTTP client.
type Client struct {
	baseURL    string
	password   string
	httpClient *http.Client
}

// New creates a Client for the given rspamd base URL.
func New(baseURL, password string, timeout time.Duration) *Client {
	return &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		password: password,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// rspamdResponse is the JSON response from rspamd's /checkv2 endpoint.
type rspamdResponse struct {
	Score  float64 `json:"score"`
	Action string  `json:"action"`
	IsSpam bool    `json:"is_spam"`
}

// CheckOptions carries per-message metadata for rspamd.
type CheckOptions struct {
	From       string
	Recipients []string
	IP         string
	Helo       string
}

// Check submits msg to rspamd and returns the result.
func (c *Client) Check(ctx context.Context, msg []byte, opts CheckOptions) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/checkv2", bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	if opts.From != "" {
		req.Header.Set("From", opts.From)
	}
	for _, rcpt := range opts.Recipients {
		req.Header.Add("Rcpt", rcpt)
	}
	if opts.IP != "" {
		req.Header.Set("IP", opts.IP)
	}
	if opts.Helo != "" {
		req.Header.Set("Helo", opts.Helo)
	}
	if c.password != "" {
		req.Header.Set("Password", c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rspamd request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("rspamd status %d: %s", resp.StatusCode, body)
	}

	var r rspamdResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("decode rspamd response: %w", err)
	}

	return &Result{
		Score:  r.Score,
		Action: r.Action,
		IsSpam: r.IsSpam,
	}, nil
}

// Ping checks that rspamd is reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ping", nil)
	if err != nil {
		return fmt.Errorf("build ping request: %w", err)
	}
	if c.password != "" {
		req.Header.Set("Password", c.password)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rspamd ping: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rspamd ping status %d", resp.StatusCode)
	}
	return nil
}
