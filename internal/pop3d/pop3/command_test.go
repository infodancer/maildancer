package pop3

import (
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantCmd     string
		wantArgs    []string
		wantErr     bool
	}{
		{
			name:     "Simple command without args",
			line:     "QUIT",
			wantCmd:  "QUIT",
			wantArgs: []string{},
			wantErr:  false,
		},
		{
			name:     "Command with one arg",
			line:     "USER alice",
			wantCmd:  "USER",
			wantArgs: []string{"alice"},
			wantErr:  false,
		},
		{
			name:     "Command with multiple args",
			line:     "COMMAND arg1 arg2 arg3",
			wantCmd:  "COMMAND",
			wantArgs: []string{"arg1", "arg2", "arg3"},
			wantErr:  false,
		},
		{
			name:     "Command with extra whitespace",
			line:     "  USER   alice  ",
			wantCmd:  "USER",
			wantArgs: []string{"alice"},
			wantErr:  false,
		},
		{
			name:     "Lowercase command",
			line:     "user alice",
			wantCmd:  "USER",
			wantArgs: []string{"alice"},
			wantErr:  false,
		},
		{
			name:     "Mixed case command",
			line:     "QuIt",
			wantCmd:  "QUIT",
			wantArgs: []string{},
			wantErr:  false,
		},
		{
			name:     "Empty line",
			line:     "",
			wantCmd:  "",
			wantArgs: nil,
			wantErr:  true,
		},
		{
			name:     "Whitespace only",
			line:     "   ",
			wantCmd:  "",
			wantArgs: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args, err := ParseCommand(tt.line)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if cmd != tt.wantCmd {
				t.Errorf("ParseCommand() cmd = %v, want %v", cmd, tt.wantCmd)
			}

			if !stringSlicesEqual(args, tt.wantArgs) {
				t.Errorf("ParseCommand() args = %v, want %v", args, tt.wantArgs)
			}
		})
	}
}

// Helper function to compare string slices
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
