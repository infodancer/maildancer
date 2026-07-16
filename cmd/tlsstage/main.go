// Command tlsstage copies a daemon's TLS certificate and key from their
// configured (often root-only, read-only-mounted) locations into a staging
// directory readable by the daemon's unprivileged service account. Run as
// root from the daemon's s6 run script before privileges are dropped.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/infodancer/maildancer/internal/tlsstage"
)

func main() {
	configPath := flag.String("config", "", "path to TOML config file (required)")
	section := flag.String("section", "", "daemon config section to read [<section>.tls] from (required)")
	outDir := flag.String("out", "", "staging directory for fullchain.pem/privkey.pem (required)")
	group := flag.String("group", "mailsvc", "group name given read access to the staged key")
	refresh := flag.Duration("refresh", 0, "re-stage when sources change, checking at this interval (0 = stage once and exit)")
	flag.Parse()

	if *configPath == "" || *section == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "usage: tlsstage -config <path> -section <name> -out <dir> [-group <name>] [-refresh <interval>]")
		os.Exit(2)
	}

	opts := tlsstage.Options{
		ConfigPath: *configPath,
		Section:    *section,
		OutDir:     *outDir,
		Group:      *group,
	}

	if *refresh <= 0 {
		if err := tlsstage.Run(opts, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "tlsstage: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Refresh mode: stage once, then re-stage whenever a source file's mtime
	// is newer than its staged copy. Errors are logged and retried on the
	// next tick -- a transiently unreadable source (e.g. mid-renewal) must
	// not kill the refresher, and RefreshOnce heals a failed initial stage
	// because the missing staged copies force a restage.
	if err := tlsstage.Run(opts, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "tlsstage: initial stage: %v\n", err)
	}
	for {
		time.Sleep(*refresh)
		restaged, err := tlsstage.RefreshOnce(opts, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tlsstage: refresh: %v\n", err)
			continue
		}
		if restaged {
			fmt.Fprintf(os.Stderr, "tlsstage: restaged TLS material for [%s] into %s\n", *section, *outDir)
		}
	}
}
