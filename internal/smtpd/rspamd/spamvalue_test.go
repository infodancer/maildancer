package rspamd

import "testing"

// TestSpamValue covers the RFC 5235 normalization. The scale matters because it
// is what user Sieve scripts compare against: go-sieve has no spamtest
// extension, and i;ascii-numeric (RFC 4790) is defined over non-negative
// integers only, so a decimal X-Spam-Score cannot be compared numerically at
// all. X-Spam-Value is the integer users can actually write rules against.
func TestSpamValue(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		required float64
		want     int
	}{
		// RFC 5235 reserves 0 for "the message was not tested". A checker that
		// reports no threshold has not produced a comparable verdict.
		{"no threshold reported", 5.0, 0, 0},
		{"negative threshold", 5.0, -1, 0},

		// 1 is "definitely not spam"; ham scores at or below zero all land there
		// rather than going out of range.
		{"zero score", 0, 15, 1},
		{"negative score", -4.2, 15, 1},

		// The band between 0 and the threshold spreads over 1..10.
		{"just above zero", 0.1, 15, 1},
		{"half the threshold", 7.5, 15, 6},
		{"the observed phish", 12.8, 15, 9},
		{"just below the threshold", 14.9, 15, 10},

		// At or above the threshold the message is spam by the checker's own
		// reckoning, so it pins at 10 and never overflows.
		{"at the threshold", 15, 15, 10},
		{"far above the threshold", 500, 15, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := spamValue(tt.score, tt.required); got != tt.want {
				t.Errorf("spamValue(%v, %v) = %d, want %d", tt.score, tt.required, got, tt.want)
			}
		})
	}
}

// TestSpamValue_InRange is a blanket guard: whatever a checker reports, the
// value stays inside the range RFC 5235 defines. A score outside 0..10 would be
// silently meaningless to any script comparing against it.
func TestSpamValue_InRange(t *testing.T) {
	scores := []float64{-1e9, -100, -0.5, 0, 0.5, 3, 14.999, 15, 1e9}
	requireds := []float64{0, 1, 5, 15, 1e6}

	for _, required := range requireds {
		for _, score := range scores {
			if got := spamValue(score, required); got < 0 || got > 10 {
				t.Errorf("spamValue(%v, %v) = %d, outside 0..10", score, required, got)
			}
		}
	}
}
