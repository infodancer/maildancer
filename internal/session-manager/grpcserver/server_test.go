package grpcserver

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestTokenFromContext_Valid(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("session-token", "abc123"))

	token, err := tokenFromContext(ctx)
	if err != nil {
		t.Fatalf("tokenFromContext() error: %v", err)
	}
	if token != "abc123" {
		t.Errorf("token = %q, want %q", token, "abc123")
	}
}

func TestTokenFromContext_MissingMetadata(t *testing.T) {
	_, err := tokenFromContext(context.Background())
	if err == nil {
		t.Fatal("expected error for missing metadata")
	}
}

func TestTokenFromContext_MissingToken(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("other-key", "value"))

	_, err := tokenFromContext(ctx)
	if err == nil {
		t.Fatal("expected error for missing session-token")
	}
}

func TestTokenFromContext_EmptyToken(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("session-token", ""))

	_, err := tokenFromContext(ctx)
	if err == nil {
		t.Fatal("expected error for empty session-token")
	}
}
