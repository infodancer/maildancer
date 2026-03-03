package auth

import "testing"

func TestDeriveKeyPair_Stub(t *testing.T) {
	pub, priv, err := DeriveKeyPair("password", "user@example.com", []byte("salt"))
	if err == nil {
		t.Fatal("expected non-nil error from stub implementation")
	}
	if pub != nil {
		t.Errorf("expected nil pub key from stub, got %v", pub)
	}
	if priv != nil {
		t.Errorf("expected nil priv key from stub, got %v", priv)
	}
}
