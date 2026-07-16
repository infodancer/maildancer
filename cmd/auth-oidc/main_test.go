package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthURL(t *testing.T) {
	tests := []struct {
		listen string
		want   string
	}{
		{":8080", "http://127.0.0.1:8080/healthz"},
		{"0.0.0.0:8080", "http://127.0.0.1:8080/healthz"},
		{"[::]:8080", "http://127.0.0.1:8080/healthz"},
		{"127.0.0.1:9000", "http://127.0.0.1:9000/healthz"},
		{"10.0.0.5:8080", "http://10.0.0.5:8080/healthz"},
		{"localhost:8080", "http://localhost:8080/healthz"},
	}
	for _, tt := range tests {
		if got := healthURL(tt.listen); got != tt.want {
			t.Errorf("healthURL(%q) = %q, want %q", tt.listen, got, tt.want)
		}
	}
}

func TestProbeHealthz_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","loaded":1}`))
	}))
	defer ts.Close()

	if err := probeHealthz(ts.URL+"/healthz", 5*time.Second); err != nil {
		t.Errorf("probeHealthz = %v, want nil", err)
	}
}

func TestProbeHealthz_Degraded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"degraded","loaded":1,"failed":1}`))
	}))
	defer ts.Close()

	if err := probeHealthz(ts.URL+"/healthz", 5*time.Second); err == nil {
		t.Error("probeHealthz = nil on 503, want error")
	}
}

func TestProbeHealthz_ConnectionRefused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := ts.URL
	ts.Close()

	if err := probeHealthz(url+"/healthz", 1*time.Second); err == nil {
		t.Error("probeHealthz = nil against closed server, want error")
	}
}
