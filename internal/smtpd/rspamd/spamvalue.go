package rspamd

import "math"

// spamValue normalizes a checker score onto the 0..10 scale RFC 5235 defines for
// the Sieve "spamtest" extension.
//
// We stamp this as X-Spam-Value rather than expecting scripts to compare
// X-Spam-Score, because the score cannot be compared in Sieve at all: go-sieve
// implements no spamtest extension, so the only numeric comparator available is
// i;ascii-numeric, and RFC 4790 defines that over non-negative integers. Against
// "12.80" it reads 12 and stops at the '.'; against a negative ham score it
// produces a value with no defined ordering. Either way a threshold rule looks
// correct and behaves arbitrarily, so the integer is what users get to compare.
//
// The scale, from RFC 5235 section 2.1:
//
//	0       the message was not tested
//	1       definitely not spam
//	2..9    increasing likelihood, spread over the band below the threshold
//	10      definitely spam
//
// required is the checker's own spam threshold. A checker that reports no
// usable threshold has produced nothing comparable, which is 0 -- not "clean".
// Ham (a score at or below zero) is 1, and anything at or above the threshold
// pins at 10, so the value never leaves the range whatever a checker reports.
func spamValue(score, required float64) int {
	if required <= 0 || math.IsNaN(required) || math.IsInf(required, 0) {
		return 0
	}
	if math.IsNaN(score) {
		return 0
	}
	if score <= 0 {
		return 1
	}
	if score >= required {
		return 10
	}

	// Spread (0, required) over 1..10, rounding to nearest. Rounding up instead
	// would make 1 reachable only at a score of exactly zero, which strands the
	// bottom bucket: a message scoring 0.1 against a threshold of 15 is
	// "definitely not spam" by any reading, not one notch up from it.
	v := 1 + int(math.Round((score/required)*9))
	return min(max(v, 1), 10)
}
