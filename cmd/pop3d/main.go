package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	// Dispatch to a subcommand before flag.Parse() so the chosen function
	// owns flag parsing. Strip the subcommand from os.Args so flag.Parse
	// sees only flags.
	var subcommand string
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		subcommand = os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	switch subcommand {
	case "", "serve":
		runServe()
	case "protocol-handler":
		runProtocolHandler()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\nusage: pop3d [serve|protocol-handler] [flags]\n", subcommand)
		os.Exit(1)
	}
}
