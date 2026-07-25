// Command reportlesshelper is a stand-in protocol-handler that dies without
// writing its fd-4 metrics report -- the child-side half of the #191 flake
// signature. TestDispatcherCountsChildThatDiesWithoutReport spawns it through
// the real dispatcher to prove the reaper counts the missing report as
// handler_failures_total{reason=empty_report} instead of silently ingesting
// an empty stream.
package main

import "os"

func main() {
	os.Exit(1)
}
