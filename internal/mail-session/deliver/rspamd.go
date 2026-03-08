package deliver

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

// SpamResult holds the outcome of a spam check.
type SpamResult struct {
	Score  float64
	Action string
	IsSpam bool
}

// rspamdResponse is the JSON response from rspamd's /checkv2 endpoint.
type rspamdResponse struct {
	Score  float64 `json:"score"`
	Action string  `json:"action"`
	IsSpam bool    `json:"is_spam"`
}

// SpamCheckOptions carries per-message metadata for rspamd.
type SpamCheckOptions struct {
	From       string
	Recipients []string
	IP         string
	Helo       string
}

// spamChecker is the rspamd /checkv2 HTTP client.
type spamChecker struct {
	baseURL    string
	password   string
	httpClient *http.Client
}

// newSpamChecker creates a spam checker for the given rspamd URL.
func newSpamChecker(baseURL, password string, timeout time.Duration) *spamChecker {
	return &spamChecker{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		password: password,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// check submits msg to rspamd /checkv2 and returns the result.
func (c *spamChecker) check(ctx context.Context, msg []byte, opts SpamCheckOptions) (*SpamResult, error) {
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

	return &SpamResult{
		Score:  r.Score,
		Action: r.Action,
		IsSpam: r.IsSpam,
	}, nil
}
