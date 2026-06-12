package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	authdomain "github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/admin"
)

// dnsResolver is the resolver used by `domain dns`; tests substitute a fake.
// nil means net.DefaultResolver.
var dnsResolver admin.Resolver

// cmdDomainDNS runs the DNS checks for a domain and prints a report.
// Failed (error-status) checks make the command return an error so scripts
// can gate on the exit code; warnings do not.
func cmdDomainDNS(paths admin.Paths, name, flagHostname, flagIP string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target, notes := resolveDNSTarget(ctx, flagHostname, flagIP, paths, name)
	for _, n := range notes {
		fmt.Println(n)
	}
	if target.Hostname == "" {
		return fmt.Errorf("no server hostname available: pass --hostname, set dns.hostname on the domain, or set [dns] hostname / smtpd.hostname in %s", defaultConfigPath)
	}

	checks, err := paths.CheckDomainDNS(ctx, dnsResolver, name, target)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "CHECK\tSTATUS\tDETAIL"); err != nil {
		return err
	}
	failed := 0
	for _, c := range checks {
		if c.Status == admin.DNSStatusError {
			failed++
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", c.Type, c.Status, c.Message); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d DNS checks failed", failed, len(checks))
	}
	return nil
}

// resolveDNSTarget determines the server identity the domain's DNS should
// reference. Hostname precedence: flag > domain dns.hostname > [dns] hostname
// in the server config > smtpd.hostname. IP precedence: flag > domain
// dns.public_ip > [dns] public_ip in the server config > the effective
// hostname's A/AAAA record (reported as derived, since that cannot
// independently verify the A record).
func resolveDNSTarget(ctx context.Context, flagHostname, flagIP string, paths admin.Paths, name string) (admin.DNSTarget, []string) {
	var target admin.DNSTarget
	var notes []string

	var domCfg authdomain.DNSConfig
	if cfg, err := authdomain.LoadDomainConfig(filepath.Join(paths.Config, name, "config.toml")); err == nil {
		domCfg = cfg.DNS
	}
	srvCfg, _ := loadServerConfig(defaultConfigPath) // nil when absent

	switch {
	case flagHostname != "":
		target.Hostname = flagHostname
	case domCfg.Hostname != "":
		target.Hostname = domCfg.Hostname
		notes = append(notes, fmt.Sprintf("hostname %s from domain config (dns.hostname)", domCfg.Hostname))
	case srvCfg != nil && srvCfg.DNS.Hostname != "":
		target.Hostname = srvCfg.DNS.Hostname
		notes = append(notes, fmt.Sprintf("hostname %s from %s ([dns] hostname)", srvCfg.DNS.Hostname, defaultConfigPath))
	case srvCfg != nil && srvCfg.SMTPD.Hostname != "":
		target.Hostname = srvCfg.SMTPD.Hostname
		notes = append(notes, fmt.Sprintf("hostname %s from %s (smtpd.hostname)", srvCfg.SMTPD.Hostname, defaultConfigPath))
	}

	switch {
	case flagIP != "":
		target.IP = flagIP
	case domCfg.PublicIP != "":
		target.IP = domCfg.PublicIP
		notes = append(notes, fmt.Sprintf("server IP %s from domain config (dns.public_ip)", domCfg.PublicIP))
	case srvCfg != nil && srvCfg.DNS.PublicIP != "":
		target.IP = srvCfg.DNS.PublicIP
		notes = append(notes, fmt.Sprintf("server IP %s from %s ([dns] public_ip)", srvCfg.DNS.PublicIP, defaultConfigPath))
	case target.Hostname != "":
		r := dnsResolver
		if r == nil {
			r = net.DefaultResolver
		}
		if addrs, err := r.LookupHost(ctx, target.Hostname); err == nil && len(addrs) > 0 {
			target.IP = addrs[0]
			notes = append(notes, fmt.Sprintf("server IP %s derived from the A record of %s (not independently verified; set dns.public_ip to pin it)", target.IP, target.Hostname))
		} else {
			notes = append(notes, fmt.Sprintf("no server IP available (%s does not resolve); IP-dependent checks will be skipped", target.Hostname))
		}
	}

	return target, notes
}
