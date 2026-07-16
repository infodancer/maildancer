package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadHandlerCredentials(t *testing.T) {
	content := `
[smtpd]
hostname = "mail.example.com"
handler_uid = 903
handler_gid = 900
handler_groups = [901, 902]
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "smtpd.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.HandlerUID != 903 {
		t.Errorf("handler_uid = %d, want 903", cfg.HandlerUID)
	}
	if cfg.HandlerGID != 900 {
		t.Errorf("handler_gid = %d, want 900", cfg.HandlerGID)
	}
	if !reflect.DeepEqual(cfg.HandlerGroups, []uint32{901, 902}) {
		t.Errorf("handler_groups = %v, want [901 902]", cfg.HandlerGroups)
	}
}

func TestLoadHandlerCredentialsDefaultZero(t *testing.T) {
	cfg := Default()
	if cfg.HandlerUID != 0 || cfg.HandlerGID != 0 || len(cfg.HandlerGroups) != 0 {
		t.Errorf("default handler credentials = %d/%d/%v, want 0/0/[]",
			cfg.HandlerUID, cfg.HandlerGID, cfg.HandlerGroups)
	}
}

func TestApplyFlagsHandlerCredentials(t *testing.T) {
	cfg := Default()
	flags := &Flags{
		HandlerUID:    903,
		HandlerGID:    900,
		HandlerGroups: []uint32{901},
	}

	result := ApplyFlags(cfg, flags)

	if result.HandlerUID != 903 {
		t.Errorf("handler_uid = %d, want 903", result.HandlerUID)
	}
	if result.HandlerGID != 900 {
		t.Errorf("handler_gid = %d, want 900", result.HandlerGID)
	}
	if !reflect.DeepEqual(result.HandlerGroups, []uint32{901}) {
		t.Errorf("handler_groups = %v, want [901]", result.HandlerGroups)
	}
}

func TestApplyFlagsHandlerCredentialsZeroDoesNotOverride(t *testing.T) {
	cfg := Default()
	cfg.HandlerUID = 903
	cfg.HandlerGID = 900
	cfg.HandlerGroups = []uint32{901}

	result := ApplyFlags(cfg, &Flags{})

	if result.HandlerUID != 903 || result.HandlerGID != 900 ||
		!reflect.DeepEqual(result.HandlerGroups, []uint32{901}) {
		t.Errorf("zero flags overrode handler credentials: %d/%d/%v",
			result.HandlerUID, result.HandlerGID, result.HandlerGroups)
	}
}

func TestValidateHandlerCredentials(t *testing.T) {
	tests := []struct {
		name    string
		uid     uint32
		gid     uint32
		groups  []uint32
		wantErr bool
	}{
		{name: "all zero (default)", wantErr: false},
		{name: "uid only", uid: 903, wantErr: false},
		{name: "uid and gid", uid: 903, gid: 900, wantErr: false},
		{name: "uid gid groups", uid: 903, gid: 900, groups: []uint32{901}, wantErr: false},
		{name: "gid without uid", gid: 900, wantErr: true},
		{name: "groups without uid", groups: []uint32{901}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.HandlerUID = tt.uid
			cfg.HandlerGID = tt.gid
			cfg.HandlerGroups = tt.groups
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGIDListValueSet(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint32
		wantErr bool
	}{
		{name: "single", input: "900", want: []uint32{900}},
		{name: "multiple", input: "900,901,902", want: []uint32{900, 901, 902}},
		{name: "spaces", input: "900, 901", want: []uint32{900, 901}},
		{name: "empty", input: "", want: nil},
		{name: "non-numeric", input: "mailsvc", wantErr: true},
		{name: "negative", input: "-1", wantErr: true},
		{name: "overflow", input: "4294967296", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v gidListValue
			err := v.Set(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Set(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil && !reflect.DeepEqual([]uint32(v), tt.want) {
				t.Errorf("Set(%q) = %v, want %v", tt.input, []uint32(v), tt.want)
			}
		})
	}
}
