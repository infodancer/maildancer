package backend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// spamLearner calls rspamd's learnspam/learnham HTTP controller endpoints.
type spamLearner struct {
	baseURL    string
	password   string
	httpClient *http.Client
}

func newSpamLearner(baseURL, password string) *spamLearner {
	return &spamLearner{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		password: password,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// learnSpam trains rspamd that this message is spam for the given user.
func (l *spamLearner) learnSpam(ctx context.Context, user string, message io.Reader) error {
	return l.learn(ctx, "learnspam", user, message)
}

// learnHam trains rspamd that this message is ham for the given user.
func (l *spamLearner) learnHam(ctx context.Context, user string, message io.Reader) error {
	return l.learn(ctx, "learnham", user, message)
}

func (l *spamLearner) learn(ctx context.Context, endpoint, user string, message io.Reader) error {
	data, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL+"/"+endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	if user != "" {
		req.Header.Set("Rcpt", user)
	}
	if l.password != "" {
		req.Header.Set("Password", l.password)
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rspamd %s returned status %d: %s", endpoint, resp.StatusCode, string(body))
	}

	return nil
}
