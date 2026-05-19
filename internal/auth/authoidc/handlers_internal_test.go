package authoidc

import (
	"strings"
	"testing"
)

func TestDeriveClientID_Stable(t *testing.T) {
	a := deriveClientID("test.example", "myapp", []string{"https://app.example/cb"})
	b := deriveClientID("test.example", "myapp", []string{"https://app.example/cb"})
	if a != b {
		t.Errorf("same inputs should yield same id: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "dyn_") {
		t.Errorf("id should be prefixed with dyn_: %q", a)
	}
}

func TestDeriveClientID_DomainVaries(t *testing.T) {
	a := deriveClientID("a.example", "myapp", []string{"https://app.example/cb"})
	b := deriveClientID("b.example", "myapp", []string{"https://app.example/cb"})
	if a == b {
		t.Errorf("different domains should yield different ids: %q", a)
	}
}

func TestDeriveClientID_ClientNameVaries(t *testing.T) {
	a := deriveClientID("test.example", "appA", []string{"https://app.example/cb"})
	b := deriveClientID("test.example", "appB", []string{"https://app.example/cb"})
	if a == b {
		t.Errorf("different client_names should yield different ids: %q", a)
	}
}

func TestDeriveClientID_RedirectURIsVary(t *testing.T) {
	a := deriveClientID("test.example", "myapp", []string{"https://a.example/cb"})
	b := deriveClientID("test.example", "myapp", []string{"https://b.example/cb"})
	if a == b {
		t.Errorf("different redirect_uris should yield different ids: %q", a)
	}
}

func TestDeriveClientID_OrderIndependent(t *testing.T) {
	a := deriveClientID("test.example", "myapp", []string{"https://a.example/cb", "https://b.example/cb"})
	b := deriveClientID("test.example", "myapp", []string{"https://b.example/cb", "https://a.example/cb"})
	if a != b {
		t.Errorf("redirect_uri order should not affect id: %q vs %q", a, b)
	}
}

// TestDeriveClientID_DoesNotMutateInput verifies the helper does not reorder
// the caller's slice (sorting happens on a clone).
func TestDeriveClientID_DoesNotMutateInput(t *testing.T) {
	uris := []string{"https://z.example/cb", "https://a.example/cb"}
	original := append([]string(nil), uris...)
	_ = deriveClientID("test.example", "myapp", uris)
	for i, v := range original {
		if uris[i] != v {
			t.Errorf("deriveClientID mutated caller's slice at %d: %q vs %q", i, uris[i], v)
		}
	}
}

func TestRegistrationMatches(t *testing.T) {
	stored := &registeredClient{
		ClientName:   "myapp",
		RedirectURIs: []string{"https://a.example/cb", "https://b.example/cb"},
	}

	// Exact match.
	if !registrationMatches(stored, "myapp", []string{"https://a.example/cb", "https://b.example/cb"}) {
		t.Error("exact match should be true")
	}

	// Order-independent match.
	if !registrationMatches(stored, "myapp", []string{"https://b.example/cb", "https://a.example/cb"}) {
		t.Error("reordered redirect_uris should still match")
	}

	// Different client_name.
	if registrationMatches(stored, "otherapp", []string{"https://a.example/cb", "https://b.example/cb"}) {
		t.Error("different client_name should not match")
	}

	// Different redirect_uri count.
	if registrationMatches(stored, "myapp", []string{"https://a.example/cb"}) {
		t.Error("different redirect_uri count should not match")
	}

	// Different redirect_uri value.
	if registrationMatches(stored, "myapp", []string{"https://a.example/cb", "https://c.example/cb"}) {
		t.Error("different redirect_uri value should not match")
	}
}
