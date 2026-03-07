package mx

import (
	"errors"
	"net"
	"testing"
)

type fakeResolver struct {
	mxRecords []*net.MX
	mxErr     error
	hostAddrs []string
	hostErr   error
}

func (f *fakeResolver) LookupMX(domain string) ([]*net.MX, error) {
	return f.mxRecords, f.mxErr
}

func (f *fakeResolver) LookupHost(domain string) ([]string, error) {
	return f.hostAddrs, f.hostErr
}

func TestLookup_MXRecords(t *testing.T) {
	r := &fakeResolver{
		mxRecords: []*net.MX{
			{Host: "mx2.example.com.", Pref: 20},
			{Host: "mx1.example.com.", Pref: 10},
		},
	}

	hosts, err := Lookup(r, "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].Name != "mx1.example.com" {
		t.Errorf("first host = %q, want mx1.example.com", hosts[0].Name)
	}
	if hosts[1].Name != "mx2.example.com" {
		t.Errorf("second host = %q, want mx2.example.com", hosts[1].Name)
	}
	if hosts[0].Port != "25" {
		t.Errorf("port = %q, want 25", hosts[0].Port)
	}
}

func TestLookup_NullMX(t *testing.T) {
	r := &fakeResolver{
		mxRecords: []*net.MX{
			{Host: ".", Pref: 0},
		},
	}

	_, err := Lookup(r, "noemail.example.com")
	if err == nil {
		t.Fatal("expected error for null MX")
	}
	var pe *PermanentError
	if !errors.As(err, &pe) {
		t.Errorf("expected PermanentError, got %T: %v", err, err)
	}
}

func TestLookup_FallbackToA(t *testing.T) {
	r := &fakeResolver{
		mxErr:     &net.DNSError{Err: "no such host", IsNotFound: true},
		hostAddrs: []string{"93.184.216.34"},
	}

	hosts, err := Lookup(r, "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Name != "example.com" {
		t.Errorf("host = %q, want example.com", hosts[0].Name)
	}
}

func TestLookup_NoRecords(t *testing.T) {
	r := &fakeResolver{
		mxErr:   &net.DNSError{Err: "no such host", IsNotFound: true},
		hostErr: &net.DNSError{Err: "no such host", IsNotFound: true},
	}

	_, err := Lookup(r, "nonexistent.example.com")
	if err == nil {
		t.Fatal("expected error for no records")
	}
	var pe *PermanentError
	if !errors.As(err, &pe) {
		t.Errorf("expected PermanentError, got %T: %v", err, err)
	}
}

func TestLookup_MXSortedByPriority(t *testing.T) {
	r := &fakeResolver{
		mxRecords: []*net.MX{
			{Host: "backup.example.com.", Pref: 30},
			{Host: "primary.example.com.", Pref: 5},
			{Host: "secondary.example.com.", Pref: 15},
		},
	}

	hosts, err := Lookup(r, "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	want := []string{"primary.example.com", "secondary.example.com", "backup.example.com"}
	for i, h := range hosts {
		if h.Name != want[i] {
			t.Errorf("hosts[%d] = %q, want %q", i, h.Name, want[i])
		}
	}
}

func TestHost_Addr(t *testing.T) {
	h := Host{Name: "mx.example.com", Port: "25"}
	if got := h.Addr(); got != "mx.example.com:25" {
		t.Errorf("Addr() = %q, want %q", got, "mx.example.com:25")
	}
}
