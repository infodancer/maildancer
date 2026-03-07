package protocol_test

import (
	"bytes"
	"testing"

	"github.com/infodancer/maildancer/internal/mail-session/protocol"
)

func TestWriteOK(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	if err := w.WriteOK(); err != nil {
		t.Fatalf("WriteOK error: %v", err)
	}
	if got := buf.String(); got != "+OK\r\n" {
		t.Errorf("got %q, want %q", got, "+OK\r\n")
	}
}

func TestWriteOKLine(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	if err := w.WriteOKLine("3 1024"); err != nil {
		t.Fatalf("WriteOKLine error: %v", err)
	}
	if got := buf.String(); got != "+OK 3 1024\r\n" {
		t.Errorf("got %q, want %q", got, "+OK 3 1024\r\n")
	}
}

func TestWriteOKLines(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	lines := []string{"uid1 512 \\Seen", "uid2 1024 "}
	if err := w.WriteOKLines(lines); err != nil {
		t.Fatalf("WriteOKLines error: %v", err)
	}
	want := "+OK 2\r\nuid1 512 \\Seen\r\nuid2 1024 \r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriteOKLines_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	if err := w.WriteOKLines([]string{}); err != nil {
		t.Fatalf("WriteOKLines error: %v", err)
	}
	if got := buf.String(); got != "+OK 0\r\n" {
		t.Errorf("got %q, want %q", got, "+OK 0\r\n")
	}
}

func TestWriteData(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	data := []byte("Hello, world!")
	if err := w.WriteData(data); err != nil {
		t.Fatalf("WriteData error: %v", err)
	}
	want := "+DATA 13\r\nHello, world!"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriteNewMail(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	lines := []string{"uid3 2048 \\Recent", "uid4 512 "}
	if err := w.WriteNewMail(lines); err != nil {
		t.Fatalf("WriteNewMail error: %v", err)
	}
	want := "+NEWMAIL 2\r\nuid3 2048 \\Recent\r\nuid4 512 \r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriteNewMail_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	if err := w.WriteNewMail([]string{}); err != nil {
		t.Fatalf("WriteNewMail error: %v", err)
	}
	if got := buf.String(); got != "+NEWMAIL 0\r\n" {
		t.Errorf("got %q, want %q", got, "+NEWMAIL 0\r\n")
	}
}

func TestWriteErr(t *testing.T) {
	var buf bytes.Buffer
	w := protocol.NewWriter(&buf)
	if err := w.WriteErr("unknown command"); err != nil {
		t.Fatalf("WriteErr error: %v", err)
	}
	if got := buf.String(); got != "-ERR unknown command\r\n" {
		t.Errorf("got %q, want %q", got, "-ERR unknown command\r\n")
	}
}
