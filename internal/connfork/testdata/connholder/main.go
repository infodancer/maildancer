// Command connholder is a stand-in protocol handler for connfork tests: it
// inherits the accepted TCP connection as fd 3 (the connfork contract) and
// holds it open until the peer closes, so a test can observe one live child
// process per connection.
package main

import (
	"io"
	"os"
)

func main() {
	conn := os.NewFile(3, "conn")
	if conn == nil {
		os.Exit(1)
	}
	_, _ = io.Copy(io.Discard, conn)
}
