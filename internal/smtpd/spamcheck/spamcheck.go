// Package spamcheck provides a generic interface for spam filtering backends.
package spamcheck

import (
	"context"
	"io"
)

// Action represents the recommended action from a spam checker.
type Action string

const (
	// ActionAccept means the message should be delivered normally.
	ActionAccept Action = "accept"
	// ActionReject means the message should be permanently rejected (5xx).
	ActionReject Action = "reject"
	// ActionTempFail means the message should be temporarily rejected (4xx).
	ActionTempFail Action = "tempfail"
	// ActionFlag means the message should be flagged but delivered.
	ActionFlag Action = "flag"
)

// CheckOptions contains options for the spam check.
type CheckOptions struct {
	// From is the envelope sender (MAIL FROM).
	From string

	// Recipients is the list of envelope recipients (RCPT TO).
	Recipients []string

	// IP is the client IP address.
	IP string

	// Helo is the HELO/EHLO hostname.
	Helo string

	// Hostname is the server hostname.
	Hostname string

	// User is the authenticated username (if any).
	User string

	// QueueID is an optional queue ID for logging.
	QueueID string
}

// CheckResult represents the result of a spam check.
type CheckResult struct {
	// CheckerName identifies which checker produced this result.
	CheckerName string

	// Score is the spam score (higher = more likely spam).
	Score float64

	// Action is the recommended action.
	Action Action

	// IsSpam indicates whether the checker considers this spam.
	IsSpam bool

	// Headers contains headers to add to the message (e.g., X-Spam-*).
	Headers map[string]string

	// RejectMessage is the message to send when rejecting (optional).
	RejectMessage string

	// Details contains checker-specific details for logging.
	Details map[string]interface{}
}

// Checker is the interface for spam filtering backends.
type Checker interface {
	// Name returns the name of this checker for logging/metrics.
	Name() string

	// Check performs a spam check on the message.
	// The message reader should be read completely; implementations may buffer it.
	Check(ctx context.Context, message io.Reader, opts CheckOptions) (*CheckResult, error)

	// Close releases any resources held by the checker.
	Close() error
}

// FailMode defines the behavior when a spam checker is unavailable or errors.
type FailMode string

const (
	// FailOpen accepts the message when the checker is unavailable.
	FailOpen FailMode = "open"
	// FailTempFail returns a temporary failure (4xx) when the checker is unavailable.
	FailTempFail FailMode = "tempfail"
	// FailReject returns a permanent failure (5xx) when the checker is unavailable.
	FailReject FailMode = "reject"
)

// Config holds common configuration for spam checkers.
type Config struct {
	// FailMode determines behavior when the checker is unavailable.
	FailMode FailMode

	// RejectThreshold is the score at or above which messages are rejected (5xx).
	RejectThreshold float64

	// TempFailThreshold is the score at or above which messages get temp failure (4xx).
	// Set to 0 to disable.
	TempFailThreshold float64

	// AddHeaders indicates whether to add spam headers to messages.
	AddHeaders bool
}

// GetFailMode returns the fail mode, defaulting to tempfail if not set.
func (c *Config) GetFailMode() FailMode {
	switch c.FailMode {
	case FailOpen, FailTempFail, FailReject:
		return c.FailMode
	default:
		return FailTempFail
	}
}

// ShouldReject returns true if the result indicates the message should be rejected.
func (r *CheckResult) ShouldReject(threshold float64) bool {
	if r.Action == ActionReject {
		return true
	}
	if threshold > 0 && r.Score >= threshold {
		return true
	}
	return false
}

// ShouldTempFail returns true if the result indicates a temporary failure.
func (r *CheckResult) ShouldTempFail(threshold float64) bool {
	if r.Action == ActionTempFail {
		return true
	}
	if threshold > 0 && r.Score >= threshold {
		return true
	}
	return false
}
