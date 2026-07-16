package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

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
	case "healthcheck":
		cmdHealthcheck()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: auth-oidc <command>")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  version      print version and exit")
	fmt.Fprintln(os.Stderr, "  serve        start the OIDC HTTP server")
	fmt.Fprintln(os.Stderr, "  healthcheck  probe the running server's /healthz; exit 0 if healthy")
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

// healthcheckTimeout bounds the probe so a wedged server fails the check
// instead of hanging the container healthcheck.
const healthcheckTimeout = 5 * time.Second

// cmdHealthcheck probes the running server's /healthz over loopback and
// exits 0 only on HTTP 200. It exists so the distroless container (no
// shell, no curl) can use its own binary as the Docker healthcheck. Config
// resolution is identical to serve: AUTH_OIDC_CONFIG or the default path.
func cmdHealthcheck() {
	cfg, err := authoidc.Load(configPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: config: %v\n", err)
		os.Exit(1)
	}
	if err := probeHealthz(healthURL(cfg.Server.Listen), healthcheckTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		os.Exit(1)
	}
}

// healthURL derives the loopback probe URL from a listen address. Wildcard
// hosts (empty, 0.0.0.0, ::) bind every interface, so the probe targets
// 127.0.0.1; explicit hosts are kept as-is.
func healthURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Not host:port shaped; let the HTTP client surface the error.
		return "http://" + listen + "/healthz"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// probeHealthz GETs url and returns nil only for HTTP 200. Any other
// status, a connection error, or a timeout is a failure.
func probeHealthz(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return nil
}
