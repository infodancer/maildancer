package idrange

import "testing"

func TestAllocatableAndReserved(t *testing.T) {
	tests := []struct {
		id          uint32
		allocatable bool
		reserved    bool
	}{
		{0, false, false},         // root/unset: valid nowhere
		{1, false, true},          // daemon
		{900, false, true},        // mailsvc
		{903, false, true},        // smtpd service account
		{9999, false, true},       // last reserved id below the floor
		{10000, true, false},      // AllocatorFloor: first allocatable
		{10014, true, false},      // a real domain gid
		{65531, true, false},      // last allocatable before the band
		{65532, false, true},      // distroless nonroot
		{65533, false, true},      // nogroup
		{65534, false, true},      // nobody
		{65535, false, true},      // 16-bit -1
		{65536, true, false},      // allocatable resumes above the band
		{4294967295, true, false}, // MaxUint32
	}
	for _, tt := range tests {
		if got := Allocatable(tt.id); got != tt.allocatable {
			t.Errorf("Allocatable(%d) = %v, want %v", tt.id, got, tt.allocatable)
		}
		if got := Reserved(tt.id); got != tt.reserved {
			t.Errorf("Reserved(%d) = %v, want %v", tt.id, got, tt.reserved)
		}
	}
}
