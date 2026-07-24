// Command connholder is a stand-in protocol handler for connfork tests: it
// inherits the accepted TCP connection as fd 3 (the connfork contract) and
// holds it open until the peer closes, so a test can observe one live child
// process per connection. Before exiting it writes a fixed report payload to
// fd 4, exercising the report pipe when the test configured one; without a
// pipe the write fails on the invalid fd and is deliberately ignored, exactly
// as a real handler ignores an unconfigured report fd.
package main

import (
	"io"
	"os"
)

// reportPayload is asserted verbatim by the report-pipe test.
const reportPayload = "connholder-report-payload"

func main() {
	conn := os.NewFile(3, "conn")
	if conn == nil {
		os.Exit(1)
	}
	_, _ = io.Copy(io.Discard, conn)

	if report := os.NewFile(4, "report-pipe"); report != nil {
		_, _ = report.WriteString(reportPayload)
		_ = report.Close()
	}
}
