package pop3

import (
	"strings"
	"testing"
)

func TestReadAuthSignal_Valid(t *testing.T) {
	input := "AUTH 1\r\nUSER:alice@example.com\r\nEND\r\n"
	sig, err := readAuthSignal(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readAuthSignal: %v", err)
	}
	if sig.Version != 1 {
		t.Errorf("expected Version 1, got %d", sig.Version)
	}
	if sig.Username != "alice@example.com" {
		t.Errorf("expected username alice@example.com, got %q", sig.Username)
	}
}

func TestReadAuthSignal_ValidNoCarriageReturn(t *testing.T) {
	// LF-only lines should also be accepted (TrimRight strips \r)
	input := "AUTH 1\nUSER:bob@test.org\nEND\n"
	sig, err := readAuthSignal(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readAuthSignal: %v", err)
	}
	if sig.Username != "bob@test.org" {
		t.Errorf("expected bob@test.org, got %q", sig.Username)
	}
}

func TestReadAuthSignal_UnexpectedEOF(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"auth only", "AUTH 1\r\n"},
		{"auth and user", "AUTH 1\r\nUSER:alice@example.com\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readAuthSignal(strings.NewReader(tc.input))
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestReadAuthSignal_BadVersion(t *testing.T) {
	cases := []string{
		"AUTH 2\r\nUSER:alice@example.com\r\nEND\r\n",
		"AUTH 0\r\nUSER:alice@example.com\r\nEND\r\n",
		"AUTH abc\r\nUSER:alice@example.com\r\nEND\r\n",
	}
	for _, input := range cases {
		_, err := readAuthSignal(strings.NewReader(input))
		if err == nil {
			t.Errorf("expected error for input %q, got nil", input)
		}
	}
}

func TestReadAuthSignal_MissingPrefix(t *testing.T) {
	// Wrong first line
	_, err := readAuthSignal(strings.NewReader("HELLO 1\r\nUSER:alice@example.com\r\nEND\r\n"))
	if err == nil {
		t.Error("expected error for bad AUTH line, got nil")
	}

	// Wrong second line
	_, err = readAuthSignal(strings.NewReader("AUTH 1\r\nUSERNAME:alice@example.com\r\nEND\r\n"))
	if err == nil {
		t.Error("expected error for bad USER line, got nil")
	}

	// Wrong third line
	_, err = readAuthSignal(strings.NewReader("AUTH 1\r\nUSER:alice@example.com\r\nDONE\r\n"))
	if err == nil {
		t.Error("expected error for bad END line, got nil")
	}
}

func TestReadAuthSignal_EmptyUsername(t *testing.T) {
	_, err := readAuthSignal(strings.NewReader("AUTH 1\r\nUSER:\r\nEND\r\n"))
	if err == nil {
		t.Error("expected error for empty username, got nil")
	}
}
