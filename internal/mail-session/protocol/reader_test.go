package protocol_test

import (
	"io"
	"strings"
	"testing"

	"github.com/infodancer/maildancer/internal/mail-session/protocol"
)

func TestReadCommand_CRLF(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("MAILBOX user@example.com\r\n"))
	cmd, err := r.ReadCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Name != "MAILBOX" {
		t.Errorf("Name = %q, want %q", cmd.Name, "MAILBOX")
	}
	if len(cmd.Args) != 1 || cmd.Args[0] != "user@example.com" {
		t.Errorf("Args = %v, want [user@example.com]", cmd.Args)
	}
}

func TestReadCommand_LFOnly(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("LIST\n"))
	cmd, err := r.ReadCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Name != "LIST" {
		t.Errorf("Name = %q, want %q", cmd.Name, "LIST")
	}
	if len(cmd.Args) != 0 {
		t.Errorf("Args = %v, want []", cmd.Args)
	}
}

func TestReadCommand_MultipleArgs(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("HEADERS uid123 5\r\n"))
	cmd, err := r.ReadCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Name != "HEADERS" {
		t.Errorf("Name = %q, want %q", cmd.Name, "HEADERS")
	}
	if len(cmd.Args) != 2 || cmd.Args[0] != "uid123" || cmd.Args[1] != "5" {
		t.Errorf("Args = %v, want [uid123 5]", cmd.Args)
	}
}

func TestReadCommand_EOF(t *testing.T) {
	r := protocol.NewReader(strings.NewReader(""))
	_, err := r.ReadCommand()
	if err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

func TestReadCommand_MultipleCommands(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("LIST\r\nSTAT\r\n"))
	cmd, err := r.ReadCommand()
	if err != nil {
		t.Fatalf("first read error: %v", err)
	}
	if cmd.Name != "LIST" {
		t.Errorf("first Name = %q, want LIST", cmd.Name)
	}
	cmd, err = r.ReadCommand()
	if err != nil {
		t.Fatalf("second read error: %v", err)
	}
	if cmd.Name != "STAT" {
		t.Errorf("second Name = %q, want STAT", cmd.Name)
	}
	_, err = r.ReadCommand()
	if err != io.EOF {
		t.Errorf("third err = %v, want io.EOF", err)
	}
}

func TestReadCommand_NoArgs(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("COMMIT\r\n"))
	cmd, err := r.ReadCommand()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.Name != "COMMIT" {
		t.Errorf("Name = %q, want COMMIT", cmd.Name)
	}
	if len(cmd.Args) != 0 {
		t.Errorf("Args = %v, want []", cmd.Args)
	}
}

func TestReadBytes_AfterCommand(t *testing.T) {
	// Simulates the APPEND body read: command line + raw bytes immediately following.
	input := "APPEND INBOX 5 NONE 2024-01-01T00:00:00Z\r\nhello"
	r := protocol.NewReader(strings.NewReader(input))
	cmd, err := r.ReadCommand()
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Name != "APPEND" {
		t.Fatalf("Name = %q, want APPEND", cmd.Name)
	}
	data, err := r.ReadBytes(5)
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("data = %q, want %q", data, "hello")
	}
}

func TestReadBytes_ExactCount(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("world"))
	data, err := r.ReadBytes(5)
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("data = %q, want %q", data, "world")
	}
}

func TestReadBytes_ShortRead(t *testing.T) {
	r := protocol.NewReader(strings.NewReader("hi"))
	_, err := r.ReadBytes(10)
	if err == nil {
		t.Error("expected error on short read, got nil")
	}
}
