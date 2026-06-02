// Package rspamd provides a spam checker implementation using rspamd.
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

	"github.com/infodancer/maildancer/internal/smtpd/spamcheck"
)

// RspamdAction represents the action from rspamd's response.
type RspamdAction string

const (
	// RspamdActionNoAction means the message should be delivered normally.
	RspamdActionNoAction RspamdAction = "no action"
	// RspamdActionGreylist means the message should be greylisted.
	RspamdActionGreylist RspamdAction = "greylist"
	// RspamdActionAddHeader means spam headers should be added.
	RspamdActionAddHeader RspamdAction = "add header"
	// RspamdActionRewriteSubject means the subject should be rewritten.
	RspamdActionRewriteSubject RspamdAction = "rewrite subject"
	// RspamdActionSoftReject means temporary rejection (4xx).
	RspamdActionSoftReject RspamdAction = "soft reject"
	// RspamdActionReject means permanent rejection (5xx).
	RspamdActionReject RspamdAction = "reject"
)

// RspamdResult represents the raw result from rspamd.
type RspamdResult struct {
	Score         float64                 `json:"score"`
	RequiredScore float64                 `json:"required_score"`
	Action        RspamdAction            `json:"action"`
	IsSpam        bool                    `json:"is_spam"`
	Subject       string                  `json:"subject,omitempty"`
	Symbols       map[string]SymbolResult `json:"symbols,omitempty"`
	URLs          []string                `json:"urls,omitempty"`
	Emails        []string                `json:"emails,omitempty"`
	MessageID     string                  `json:"message-id,omitempty"`
	DKIMSig       string                  `json:"dkim-signature,omitempty"`
	Milter        *MilterResult           `json:"milter,omitempty"`
}

// SymbolResult represents a matched rule/symbol.
type SymbolResult struct {
	Name        string   `json:"name"`
	Score       float64  `json:"score"`
	MetricScore float64  `json:"metric_score,omitempty"`
	Description string   `json:"description,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// MilterResult contains milter-specific headers to add/modify.
type MilterResult struct {
	AddHeaders    map[string]HeaderValue `json:"add_headers,omitempty"`
	RemoveHeaders map[string]int         `json:"remove_headers,omitempty"`
}

// HeaderValue represents a header value with optional order.
type HeaderValue struct {
	Value string `json:"value"`
	Order int    `json:"order,omitempty"`
}

// Checker implements spamcheck.Checker using rspamd.
type Checker struct {
	baseURL    string
	password   string
	httpClient *http.Client
}

// NewChecker creates a new rspamd checker.
func NewChecker(baseURL string, password string, timeout time.Duration) *Checker {
	return &Checker{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		password: password,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the name of this checker.
func (c *Checker) Name() string {
	return "rspamd"
}

// Check performs a spam check using rspamd.
func (c *Checker) Check(ctx context.Context, message io.Reader, opts spamcheck.CheckOptions) (*spamcheck.CheckResult, error) {
	// Read message into buffer for the request
	msgData, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/checkv2", bytes.NewReader(msgData))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set required headers
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

	if opts.Hostname != "" {
		req.Header.Set("Hostname", opts.Hostname)
	}

	if opts.User != "" {
		req.Header.Set("User", opts.User)
	}

	if opts.QueueID != "" {
		req.Header.Set("Queue-Id", opts.QueueID)
	}

	if c.password != "" {
		req.Header.Set("Password", c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rspamd returned status %d: %s", resp.StatusCode, string(body))
	}

	var rspamdResult RspamdResult
	if err := json.NewDecoder(resp.Body).Decode(&rspamdResult); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return c.convertResult(&rspamdResult), nil
}

// convertResult converts an rspamd result to a generic CheckResult.
func (c *Checker) convertResult(r *RspamdResult) *spamcheck.CheckResult {
	result := &spamcheck.CheckResult{
		CheckerName: "rspamd",
		Score:       r.Score,
		IsSpam:      r.IsSpam,
		Headers:     c.buildHeaders(r),
		Details: map[string]interface{}{
			"required_score": r.RequiredScore,
			"rspamd_action":  r.Action,
		},
	}

	// Convert rspamd action to generic action
	switch r.Action {
	case RspamdActionReject:
		result.Action = spamcheck.ActionReject
		result.RejectMessage = fmt.Sprintf("Message rejected as spam (score %.1f)", r.Score)
	case RspamdActionSoftReject, RspamdActionGreylist:
		result.Action = spamcheck.ActionTempFail
		result.RejectMessage = "Message deferred, please try again later"
	case RspamdActionAddHeader, RspamdActionRewriteSubject:
		result.Action = spamcheck.ActionFlag
	default:
		result.Action = spamcheck.ActionAccept
	}

	return result
}

// buildHeaders creates X-Spam-* headers from rspamd result.
func (c *Checker) buildHeaders(r *RspamdResult) map[string]string {
	headers := make(map[string]string)

	// X-Spam-Status
	status := "No"
	if r.IsSpam {
		status = "Yes"
	}
	headers["X-Spam-Status"] = fmt.Sprintf("%s, score=%.2f required=%.2f", status, r.Score, r.RequiredScore)

	// X-Spam-Score
	headers["X-Spam-Score"] = fmt.Sprintf("%.2f", r.Score)

	// X-Spam-Flag
	if r.IsSpam {
		headers["X-Spam-Flag"] = "YES"
	} else {
		headers["X-Spam-Flag"] = "NO"
	}

	// X-Spam-Checker
	headers["X-Spam-Checker"] = "rspamd"

	// If milter headers are present, add them
	if r.Milter != nil {
		for name, hv := range r.Milter.AddHeaders {
			// Skip headers we already set
			if !strings.HasPrefix(strings.ToLower(name), "x-spam-") {
				headers[name] = hv.Value
			}
		}
	}

	return headers
}

// Close releases resources (no-op for rspamd as it uses HTTP).
func (c *Checker) Close() error {
	return nil
}

// Ping checks if rspamd is available.
func (c *Checker) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/ping", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	if c.password != "" {
		req.Header.Set("Password", c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rspamd returned status %d", resp.StatusCode)
	}

	return nil
}

// Ensure Checker implements spamcheck.Checker
var _ spamcheck.Checker = (*Checker)(nil)
