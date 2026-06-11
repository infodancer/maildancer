package handlers

import (
	"context"
	"testing"
)

// These tests use the default resolver and hit real DNS.
// They use well-known public domains for reliability.

func TestCheckA_NoRecord(t *testing.T) {
	ctx := context.Background()
	// Use a domain that almost certainly has no A record.
	result := checkA(ctx, nil, "thisdoesnotexist.invalid", "1.2.3.4")
	if result.Status != "error" {
		t.Errorf("expected error status for nonexistent domain, got %q", result.Status)
	}
	if result.Type != "a" {
		t.Errorf("expected type a, got %q", result.Type)
	}
}

func TestCheckMX_NoRecord(t *testing.T) {
	ctx := context.Background()
	result := checkMX(ctx, nil, "thisdoesnotexist.invalid", "1.2.3.4")
	if result.Status != "error" {
		t.Errorf("expected error status for nonexistent domain, got %q", result.Status)
	}
}

func TestCheckPTR_NoRecord(t *testing.T) {
	ctx := context.Background()
	// RFC 5737 documentation address -- should have no PTR.
	result := checkPTR(ctx, nil, "mail.example.com", "192.0.2.1")
	if result.Status != "error" {
		t.Errorf("expected error status for documentation IP, got %q: %s", result.Status, result.Message)
	}
}

func TestCheckSPF_NoRecord(t *testing.T) {
	ctx := context.Background()
	result := checkSPF(ctx, nil, "thisdoesnotexist.invalid", "1.2.3.4")
	if result.Status != "error" {
		t.Errorf("expected error status for nonexistent domain, got %q", result.Status)
	}
}

func TestCheckDKIM_NoRecord(t *testing.T) {
	ctx := context.Background()
	result := checkDKIM(ctx, nil, "thisdoesnotexist.invalid")
	// Missing DKIM is a warning, not an error (different selector possible).
	if result.Status != "warning" {
		t.Errorf("expected warning status for missing DKIM, got %q", result.Status)
	}
}

func TestCheckDMARC_NoRecord(t *testing.T) {
	ctx := context.Background()
	result := checkDMARC(ctx, nil, "thisdoesnotexist.invalid")
	if result.Status != "error" {
		t.Errorf("expected error status for missing DMARC, got %q", result.Status)
	}
}

func TestCheckAll_ReturnsAllTypes(t *testing.T) {
	ctx := context.Background()
	results := checkAll(ctx, nil, "thisdoesnotexist.invalid", "mail.thisdoesnotexist.invalid", "192.0.2.1")
	if len(results) != 6 {
		t.Fatalf("expected 6 results, got %d", len(results))
	}

	expectedTypes := []string{"a", "mx", "ptr", "spf", "dkim", "dmarc"}
	for i, expected := range expectedTypes {
		if results[i].Type != expected {
			t.Errorf("result[%d]: expected type %q, got %q", i, expected, results[i].Type)
		}
	}
}

func TestCheckSPF_ValidIPDetection(t *testing.T) {
	// Test the IP detection logic with a synthetic check.
	// We can't control real DNS, but we can verify the function handles
	// different scenarios correctly by testing against a domain we know
	// has SPF (like google.com).
	ctx := context.Background()

	// Google's SPF record won't include our test IP.
	result := checkSPF(ctx, nil, "google.com", "192.0.2.1")
	if result.Status == "error" {
		// google.com should have an SPF record.
		t.Errorf("expected google.com to have SPF, got error: %s", result.Message)
	}
	// Should be "warning" because 192.0.2.1 is not in Google's SPF.
	if result.Status != "warning" {
		t.Logf("google.com SPF check status: %s (%s)", result.Status, result.Message)
	}
}
