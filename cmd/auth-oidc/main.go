package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/infodancer/maildancer/internal/auth/authoidc"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("auth-oidc %s\n", version)
	case "serve":
		cmdServe()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: auth-oidc <command>")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  version   print version and exit")
	fmt.Fprintln(os.Stderr, "  serve     start the OIDC HTTP server")
}

func configPath() string {
	if p := os.Getenv("AUTH_OIDC_CONFIG"); p != "" {
		return p
	}
	return "/etc/auth-oidc/config.toml"
}

func cmdServe() {
	cfg, err := authoidc.Load(configPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	srv, err := authoidc.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server init: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = srv.Close() }()

	fmt.Printf("auth-oidc %s listening on %s\n", version, cfg.Server.Listen)
	if err := http.ListenAndServe(cfg.Server.Listen, srv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}
