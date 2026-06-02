//go:build integration

package smtp_test

// Integration tests require a running session-manager and are not run
// as part of the normal test suite. They are executed separately with
// the "integration" build tag.
//
// TODO: Add integration tests that connect to a real session-manager instance.
