package protocol

import (
	"bufio"
	"fmt"
	"io"
)

// Writer wraps a bufio.Writer and formats session pipe responses.
type Writer struct {
	w *bufio.Writer
}

// NewWriter returns a Writer that writes to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: bufio.NewWriter(w)}
}

// WriteOK writes "+OK\r\n" and flushes.
func (w *Writer) WriteOK() error {
	_, err := fmt.Fprintf(w.w, "+OK\r\n")
	if err != nil {
		return err
	}
	return w.w.Flush()
}

// WriteOKLine writes "+OK <data>\r\n" and flushes.
func (w *Writer) WriteOKLine(data string) error {
	_, err := fmt.Fprintf(w.w, "+OK %s\r\n", data)
	if err != nil {
		return err
	}
	return w.w.Flush()
}

// WriteOKLines writes "+OK <count>\r\n" followed by each line with "\r\n" and flushes.
func (w *Writer) WriteOKLines(lines []string) error {
	_, err := fmt.Fprintf(w.w, "+OK %d\r\n", len(lines))
	if err != nil {
		return err
	}
	for _, line := range lines {
		if _, err = fmt.Fprintf(w.w, "%s\r\n", line); err != nil {
			return err
		}
	}
	return w.w.Flush()
}

// WriteData writes "+DATA <size>\r\n" followed by the raw data bytes and flushes.
func (w *Writer) WriteData(data []byte) error {
	_, err := fmt.Fprintf(w.w, "+DATA %d\r\n", len(data))
	if err != nil {
		return err
	}
	if _, err = w.w.Write(data); err != nil {
		return err
	}
	return w.w.Flush()
}

// WriteErr writes "-ERR <reason>\r\n" and flushes.
func (w *Writer) WriteErr(reason string) error {
	_, err := fmt.Fprintf(w.w, "-ERR %s\r\n", reason)
	if err != nil {
		return err
	}
	return w.w.Flush()
}
