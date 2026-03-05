package msgstore

import "testing"

func TestSpecialUseFor(t *testing.T) {
	tests := []struct {
		folder string
		want   string
	}{
		{"Junk", "\\Junk"},
		{"Trash", "\\Trash"},
		{"Sent", "\\Sent"},
		{"Drafts", "\\Drafts"},
		{"List", ""},
		{"Bulk", ""},
		{"INBOX", ""},
		{"Nonexistent", ""},
	}
	for _, tt := range tests {
		got := SpecialUseFor(tt.folder)
		if got != tt.want {
			t.Errorf("SpecialUseFor(%q) = %q, want %q", tt.folder, got, tt.want)
		}
	}
}

func TestResolveFolder(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Spam", "Junk"},
		{"Junk", "Junk"},
		{"Sent", "Sent"},
		{"INBOX", "INBOX"},
		{"CustomFolder", "CustomFolder"},
	}
	for _, tt := range tests {
		got := ResolveFolder(tt.input)
		if got != tt.want {
			t.Errorf("ResolveFolder(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDefaultFolders_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, f := range DefaultFolders {
		if seen[f.Name] {
			t.Errorf("duplicate default folder: %s", f.Name)
		}
		seen[f.Name] = true
	}
}
