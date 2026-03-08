package backend

import (
	"testing"
)

func TestGrpcStoreImplementsRescanner(t *testing.T) {
	// Compile-time check is in grpc_store.go; this test verifies the
	// rescanner interface assertion works at runtime too.
	var _ rescanner = (*grpcStore)(nil)
}

func TestGrpcStoreCloseNilFields(t *testing.T) {
	// Close should not panic when fields are nil (e.g. partial init failure).
	gs := &grpcStore{}
	if err := gs.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
