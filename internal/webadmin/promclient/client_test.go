package promclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func prometheusHandler(t *testing.T, results []map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		samples := make([]map[string]any, 0, len(results))
		for _, m := range results {
			samples = append(samples, m)
		}
		resp := map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result":     samples,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func sample(metric map[string]string, value string) map[string]any {
	return map[string]any{
		"metric": metric,
		"value":  []any{1234567890, value},
	}
}

func TestScalar_SingleURL(t *testing.T) {
	srv := httptest.NewServer(prometheusHandler(t, []map[string]any{
		sample(map[string]string{}, "42"),
	}))
	defer srv.Close()

	c := New([]string{srv.URL})
	got := c.Scalar(context.Background(), "some_metric")
	if got != 42 {
		t.Errorf("Scalar = %v, want 42", got)
	}
}

func TestScalar_MultipleURLsSummed(t *testing.T) {
	srv1 := httptest.NewServer(prometheusHandler(t, []map[string]any{
		sample(map[string]string{}, "10"),
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(prometheusHandler(t, []map[string]any{
		sample(map[string]string{}, "5"),
	}))
	defer srv2.Close()

	c := New([]string{srv1.URL, srv2.URL})
	got := c.Scalar(context.Background(), "some_metric")
	if got != 15 {
		t.Errorf("Scalar = %v, want 15", got)
	}
}

func TestScalar_Unavailable(t *testing.T) {
	c := New([]string{})
	got := c.Scalar(context.Background(), "some_metric")
	if got != 0 {
		t.Errorf("Scalar (no URLs) = %v, want 0", got)
	}
}

func TestScalar_UnreachableReturnsZero(t *testing.T) {
	c := New([]string{"http://localhost:1"}) // nothing listening
	got := c.Scalar(context.Background(), "some_metric")
	if got != 0 {
		t.Errorf("Scalar (unreachable) = %v, want 0", got)
	}
}

func TestLabelValues_Single(t *testing.T) {
	srv := httptest.NewServer(prometheusHandler(t, []map[string]any{
		sample(map[string]string{"domain": "example.com"}, "100"),
		sample(map[string]string{"domain": "other.com"}, "50"),
	}))
	defer srv.Close()

	c := New([]string{srv.URL})
	got := c.LabelValues(context.Background(), "some_metric", "domain")
	if got["example.com"] != 100 {
		t.Errorf("example.com = %v, want 100", got["example.com"])
	}
	if got["other.com"] != 50 {
		t.Errorf("other.com = %v, want 50", got["other.com"])
	}
}

func TestLabelValues_AggregatedAcrossURLs(t *testing.T) {
	srv1 := httptest.NewServer(prometheusHandler(t, []map[string]any{
		sample(map[string]string{"domain": "example.com"}, "60"),
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(prometheusHandler(t, []map[string]any{
		sample(map[string]string{"domain": "example.com"}, "40"),
		sample(map[string]string{"domain": "other.com"}, "20"),
	}))
	defer srv2.Close()

	c := New([]string{srv1.URL, srv2.URL})
	got := c.LabelValues(context.Background(), "some_metric", "domain")
	if got["example.com"] != 100 {
		t.Errorf("example.com = %v, want 100", got["example.com"])
	}
	if got["other.com"] != 20 {
		t.Errorf("other.com = %v, want 20", got["other.com"])
	}
}

func TestAvailable(t *testing.T) {
	if New([]string{}).Available() {
		t.Error("expected Available=false with no URLs")
	}
	if !New([]string{"http://localhost:9090"}).Available() {
		t.Error("expected Available=true with a URL")
	}
}
