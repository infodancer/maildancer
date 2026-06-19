// Package kdfcost holds the argon2id cost profile shared by the two
// passphrase-based key-wrap paths: keyseal's legacy single-key blobs and
// keyring's passphrase slots. Both derive a wrap-key from a user password, so
// they share one cost profile rather than duplicating the numbers.
//
// It is an internal package: only this module can read it, and only the test
// binaries lower it (to keep argon2id off the critical path -- see issue #114).
// Production code treats Default as read-only. This is deliberately NOT the
// auth-path verifier KDF; that cost lives elsewhere and is unaffected.
package kdfcost

// Params is an argon2id cost profile for a passphrase key-wrap derivation.
type Params struct {
	Time    uint32
	Memory  uint32 // in KiB
	Threads uint8
}

// Default is the cost applied to new passphrase derivations. Secure by default:
// RFC 9106's second recommended profile (64 MiB, t=3, p=4). Tests overwrite it
// in TestMain before any derivation runs; production never mutates it.
var Default = Params{Time: 3, Memory: 64 * 1024, Threads: 4}
