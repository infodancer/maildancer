// Command queue-manager drives the infodancer mail queue retry loop.
// It scans the queue directory for pending envelopes, applies exponential
// backoff based on envelope file mtime, and invokes mail-remote for delivery.
//
// Usage:
//
//	queue-manager [flags]
//
// Flags:
//
//	--queue      path    Root of the mail queue directory (required).
//	--binary     path    Path to the mail-remote binary (default: mail-remote in PATH).
//	--smarthost  h:port  Pass --smarthost to mail-remote for all deliveries.
//	--smarthost-user u   Pass --smarthost-user to mail-remote.
//	--interval    dur     How often to scan the queue (default: 1m).
//	--message-ttl dur     Default message TTL for backoff calculation (default: 168h).
//	--once                Scan once and exit (useful for cron / testing).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/infodancer/maildancer/internal/queue-manager/scheduler"
)

func main() {
	if err := run(); err != nil {
		slog.Error("queue-manager", "error", err)
		os.Exit(1)
	}
}

func run() error {
	queueDir := flag.String("queue", "", "root of the mail queue directory (required)")
	binary := flag.String("binary", "mail-remote", "path to the mail-remote binary")
	smarthostAddr := flag.String("smarthost", "", "SMTP smarthost address (host:port)")
	smarthostUser := flag.String("smarthost-user", "", "SMTP AUTH username for smarthost")
	interval := flag.Duration("interval", time.Minute, "queue scan interval")
	messageTTL := flag.Duration("message-ttl", 7*24*time.Hour, "default message TTL (for backoff calculation)")
	once := flag.Bool("once", false, "scan once and exit")
	flag.Parse()

	if *queueDir == "" {
		return fmt.Errorf("--queue is required")
	}

	cfg := scheduler.Config{
		QueueDir:      *queueDir,
		Binary:        *binary,
		SmarthostAddr: *smarthostAddr,
		SmarthostUser: *smarthostUser,
		Interval:      *interval,
		MessageTTL:    *messageTTL,
	}

	sched := scheduler.New(cfg)

	if *once {
		return sched.RunOnce()
	}

	sched.Run()
	return nil
}
