// Package promclient provides a thin wrapper over the Prometheus HTTP query API.
// It supports multiple Prometheus base URLs and aggregates results by summing
// values across instances, enabling multi-node deployments.
package promclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client queries one or more Prometheus instances and aggregates results.
type Client struct {
	urls       []string
	httpClient *http.Client
}

// New creates a Client for the given Prometheus base URLs.
// An empty slice is valid; all queries will return zero values.
func New(urls []string) *Client {
	return &Client{
		urls: urls,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Available reports whether at least one Prometheus URL is configured.
func (c *Client) Available() bool {
	return len(c.urls) > 0
}

// Scalar runs a PromQL query expected to return a single scalar result.
// When multiple URLs are configured, values are summed across instances.
// Returns 0 if Prometheus is unreachable or returns no data.
func (c *Client) Scalar(ctx context.Context, query string) float64 {
	var total float64
	for _, base := range c.urls {
		v, err := c.queryScalar(ctx, base, query)
		if err == nil {
			total += v
		}
	}
	return total
}

// LabelValues runs a PromQL query that groups by a single label.
// Returns a map of label value → count summed across all configured URLs.
// Never returns nil.
func (c *Client) LabelValues(ctx context.Context, query, label string) map[string]float64 {
	result := make(map[string]float64)
	for _, base := range c.urls {
		m, err := c.queryLabelValues(ctx, base, query, label)
		if err != nil {
			continue
		}
		for k, v := range m {
			result[k] += v
		}
	}
	return result
}

// --- internal ---

// promResponse is the envelope returned by the Prometheus HTTP API.
type promResponse struct {
	Status string   `json:"status"`
	Data   promData `json:"data"`
}

type promData struct {
	ResultType string       `json:"resultType"`
	Result     []promSample `json:"result"`
}

type promSample struct {
	Metric map[string]string  `json:"metric"`
	Value  [2]json.RawMessage `json:"value"` // [timestamp, value_string]
}

func (s promSample) floatValue() (float64, error) {
	var raw string
	if err := json.Unmarshal(s.Value[1], &raw); err != nil {
		return 0, err
	}
	return strconv.ParseFloat(raw, 64)
}

func (c *Client) query(ctx context.Context, base, promQL string) ([]promSample, error) {
	endpoint := base + "/api/v1/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("query", promQL)
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus returned HTTP %d", resp.StatusCode)
	}

	var pr promResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	if pr.Status != "success" {
		return nil, fmt.Errorf("prometheus status: %s", pr.Status)
	}
	return pr.Data.Result, nil
}

func (c *Client) queryScalar(ctx context.Context, base, promQL string) (float64, error) {
	samples, err := c.query(ctx, base, promQL)
	if err != nil || len(samples) == 0 {
		return 0, err
	}
	return samples[0].floatValue()
}

func (c *Client) queryLabelValues(ctx context.Context, base, promQL, label string) (map[string]float64, error) {
	samples, err := c.query(ctx, base, promQL)
	if err != nil {
		return nil, err
	}
	result := make(map[string]float64, len(samples))
	for _, s := range samples {
		key := s.Metric[label]
		v, err := s.floatValue()
		if err != nil {
			continue
		}
		result[key] += v
	}
	return result, nil
}
