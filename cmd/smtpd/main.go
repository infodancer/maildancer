package main

import (
	"fmt"
	"os"

	"github.com/infodancer/maildancer/internal/smtpd/config"
)

func main() {
	flags := config.ParseFlags()

	cfg, err := config.LoadWithFlags(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// TODO: Start SMTP server with cfg
	_ = cfg
}
