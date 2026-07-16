package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/infodancer/maildancer/internal/admin"
	"github.com/infodancer/maildancer/internal/webadmin/metrics"
)

// This file closes the observability gap between FixDomain runs: the
// permission doctor executes only at provisioning and manual fix time, so
// drift in between was invisible (a production outage lived for weeks in
// exactly that window). The sweep runs admin.CheckDomain -- strictly
// read-only -- across every domain on a ticker and publishes the drifted
// path count as webadmin_domain_perm_drift{domain=...}, plus a last-run
// timestamp so a stalled sweep is itself alertable. Domain-level labels
// only, per the observability convention (no per-user series).

// runPermCheckLoop sweeps immediately, then on every interval tick until the
// context is cancelled. Started from Run when the configured interval is
// nonzero.
func (s *Server) runPermCheckLoop(ctx context.Context, interval time.Duration) {
	paths := admin.Paths{Config: s.cfg.DomainsPath, Data: s.cfg.EffectiveDataPath()}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sweepPermDrift(paths, s.logger)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepPermDrift(paths, s.logger)
		}
	}
}

// sweepPermDrift checks every domain and sets its drift gauge. A domain
// whose check fails is logged and its gauge left untouched -- a broken check
// must not read as a clean domain -- and the sweep continues. The last-run
// timestamp is stamped when the sweep completes.
func sweepPermDrift(paths admin.Paths, logger *slog.Logger) {
	domains, err := paths.ListDomains()
	if err != nil {
		logger.Error("perm drift sweep: list domains", "error", err)
		return
	}
	for _, d := range domains {
		report, err := paths.CheckDomain(d.Name)
		if err != nil {
			logger.Error("perm drift sweep: check domain", "domain", d.Name, "error", err)
			continue
		}
		drifted := report.DriftCount()
		metrics.DomainPermDrift.WithLabelValues(d.Name).Set(float64(drifted))
		if drifted > 0 {
			logger.Warn("permission drift detected", "domain", d.Name, "paths", drifted)
		}
	}
	metrics.PermCheckLastRun.SetToCurrentTime()
}
