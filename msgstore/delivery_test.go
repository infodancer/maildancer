package msgstore

import "testing"

func TestParseRecipient(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		wantAddr  string
		wantExt   string
	}{
		{
			name:     "standard with extension",
			email:    "user+folder@example.com",
			wantAddr: "user@example.com",
			wantExt:  "folder",
		},
		{
			name:     "no extension",
			email:    "user@example.com",
			wantAddr: "user@example.com",
			wantExt:  "",
		},
		{
			name:     "empty extension",
			email:    "user+@example.com",
			wantAddr: "user@example.com",
			wantExt:  "",
		},
		{
			name:     "multiple plus signs",
			email:    "user+a+b@example.com",
			wantAddr: "user@example.com",
			wantExt:  "a+b",
		},
		{
			name:     "local user no domain",
			email:    "localuser",
			wantAddr: "localuser",
			wantExt:  "",
		},
		{
			name:     "extension only",
			email:    "+ext@example.com",
			wantAddr: "@example.com",
			wantExt:  "ext",
		},
		{
			name:     "extension no domain",
			email:    "user+ext",
			wantAddr: "user",
			wantExt:  "ext",
		},
		{
			name:     "empty string",
			email:    "",
			wantAddr: "",
			wantExt:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseRecipient(tt.email)
			if got.Address != tt.wantAddr {
				t.Errorf("ParseRecipient(%q).Address = %q, want %q", tt.email, got.Address, tt.wantAddr)
			}
			if got.Extension != tt.wantExt {
				t.Errorf("ParseRecipient(%q).Extension = %q, want %q", tt.email, got.Extension, tt.wantExt)
			}
		})
	}
}
