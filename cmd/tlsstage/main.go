// Command tlsstage copies a daemon's TLS certificate and key from their
// configured (often root-only, read-only-mounted) locations into a staging
// directory readable by the daemon's unprivileged service account. Run as
// root from the daemon's s6 run script before privileges are dropped.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/infodancer/maildancer/internal/tlsstage"
)

func main() {
	configPath := flag.String("config", "", "path to TOML config file (required)")
	section := flag.String("section", "", "daemon config section to read [<section>.tls] from (required)")
	outDir := flag.String("out", "", "staging directory for fullchain.pem/privkey.pem (required)")
	group := flag.String("group", "mailsvc", "group name given read access to the staged key")
	flag.Parse()

	if *configPath == "" || *section == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "usage: tlsstage -config <path> -section <name> -out <dir> [-group <name>]")
		os.Exit(2)
	}

	opts := tlsstage.Options{
		ConfigPath: *configPath,
		Section:    *section,
		OutDir:     *outDir,
		Group:      *group,
	}
	if err := tlsstage.Run(opts, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "tlsstage: %v\n", err)
		os.Exit(1)
	}
}
