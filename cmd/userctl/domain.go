package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	authdomain "github.com/infodancer/maildancer/auth/domain"
	"github.com/infodancer/maildancer/internal/admin"
)

// runDomainSubcommand handles the `domain` subcommand and its actions:
//
//	userctl domain create <domain>
//	userctl domain del    <domain> [--force]
//	userctl domain list
//	userctl domain show   <domain>
//	userctl domain set    <domain> <key> [<value>]
//	userctl domain key    show|create|del <domain>
//
// stdin supplies the password for `domain key create --password-stdin`.
func runDomainSubcommand(args []string, paths admin.Paths, stdin io.Reader) error {
	if len(args) < 1 {
		domainUsage()
		return fmt.Errorf("domain: missing action")
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case "create":
		if len(rest) != 1 {
			domainUsage()
			return fmt.Errorf("domain create: expected <domain>")
		}
		return cmdDomainCreate(paths, strings.ToLower(strings.TrimSpace(rest[0])))

	case "del":
		force := false
		var names []string
		for _, a := range rest {
			if a == "--force" {
				force = true
			} else {
				names = append(names, a)
			}
		}
		if len(names) != 1 {
			domainUsage()
			return fmt.Errorf("domain del: expected <domain> [--force]")
		}
		return cmdDomainDel(paths, names[0], force)

	case "list":
		if len(rest) != 0 {
			domainUsage()
			return fmt.Errorf("domain list: takes no arguments")
		}
		return cmdDomainList(paths)

	case "show":
		if len(rest) != 1 {
			domainUsage()
			return fmt.Errorf("domain show: expected <domain>")
		}
		return cmdDomainShow(paths, rest[0])

	case "set":
		// Two args = unset (empty value removes the key); three = set.
		switch len(rest) {
		case 2:
			return cmdDomainSet(paths, rest[0], rest[1], "")
		case 3:
			return cmdDomainSet(paths, rest[0], rest[1], rest[2])
		default:
			domainUsage()
			return fmt.Errorf("domain set: expected <domain> <key> [<value>] (omit value to unset)")
		}

	case "fix":
		all := false
		var names []string
		for _, a := range rest {
			if a == "--all" {
				all = true
			} else {
				names = append(names, a)
			}
		}
		if all {
			if len(names) != 0 {
				domainUsage()
				return fmt.Errorf("domain fix: --all takes no domain argument")
			}
			return cmdDomainFixAll(paths)
		}
		if len(names) != 1 {
			domainUsage()
			return fmt.Errorf("domain fix: expected <domain> or --all")
		}
		return cmdDomainFix(paths, strings.ToLower(strings.TrimSpace(names[0])))

	case "key":
		return runDomainKeyAction(rest, paths, stdin)

	case "dkim":
		return runDomainDKIMAction(rest, paths)

	case "dns":
		hostname := ""
		ip := ""
		var names []string
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--hostname":
				if i+1 >= len(rest) {
					domainUsage()
					return fmt.Errorf("domain dns: --hostname requires a value")
				}
				i++
				hostname = rest[i]
			case "--ip":
				if i+1 >= len(rest) {
					domainUsage()
					return fmt.Errorf("domain dns: --ip requires a value")
				}
				i++
				ip = rest[i]
			default:
				names = append(names, rest[i])
			}
		}
		if len(names) != 1 {
			domainUsage()
			return fmt.Errorf("domain dns: expected <domain>")
		}
		return cmdDomainDNS(paths, names[0], hostname, ip)

	default:
		domainUsage()
		return fmt.Errorf("domain: unknown action %q", action)
	}
}

func cmdDomainCreate(paths admin.Paths, name string) error {
	gid, err := paths.CreateDomain(name)
	if errors.Is(err, admin.ErrDomainExists) {
		// Idempotent for IaC reconcile: an existing domain is left untouched.
		fmt.Printf("Domain %s already exists; skipping\n", name)
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Printf("Created domain %s (gid %d)\n", name, gid)
	fmt.Printf("  config: %s\n", filepath.Join(paths.Config, name))
	fmt.Printf("  data:   %s\n", filepath.Join(paths.Data, name))
	return nil
}

func cmdDomainFix(paths admin.Paths, name string) error {
	report, err := paths.FixDomain(name)
	printPermReport(report)
	if err != nil {
		return err
	}
	return nil
}

func cmdDomainFixAll(paths admin.Paths) error {
	domains, err := paths.ListDomains()
	if err != nil {
		return err
	}
	var firstErr error
	for _, d := range domains {
		report, err := paths.FixDomain(d.Name)
		printPermReport(report)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// printPermReport renders a fix report: any ids allocated, then per-path
// ownership/mode results. Off-root, chown is skipped; the note makes that
// explicit so an operator does not mistake it for success.
func printPermReport(report admin.PermReport) {
	if report.Domain == "" && len(report.Entries) == 0 {
		return
	}
	if report.Domain != "" {
		fmt.Printf("domain %s:\n", report.Domain)
	}
	for _, a := range report.Allocated {
		fmt.Printf("  allocated %s\n", a)
	}
	skippedChown := false
	for _, e := range report.Entries {
		status := "ok"
		switch {
		case e.Err != "":
			status = "ERROR: " + e.Err
		case e.Skipped && e.Changed:
			status = "mode set (chown skipped)"
			skippedChown = true
		case e.Skipped:
			status = "chown skipped"
			skippedChown = true
		case e.Changed:
			status = "fixed"
		}
		fmt.Printf("  %-60s %d:%d %04o  %s\n", e.Path, e.UID, e.GID, e.Mode.Perm(), status)
	}
	if skippedChown {
		fmt.Println("  note: ownership changes need root; re-run as root to apply uid:gid")
	}
	for _, w := range report.Warnings {
		fmt.Printf("  warning: %s\n", w)
	}
}

func cmdDomainDel(paths admin.Paths, name string, force bool) error {
	if err := paths.DeleteDomain(name, force); err != nil {
		return err
	}
	fmt.Printf("Deleted domain %s (configuration removed; mail data under %s is retained)\n",
		name, filepath.Join(paths.Data, name))
	return nil
}

func cmdDomainList(paths admin.Paths) error {
	domains, err := paths.ListDomains()
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		fmt.Println("no domains")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "DOMAIN\tAUTH\tSTORE\tGID\tUSERS"); err != nil {
		return err
	}
	for _, d := range domains {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n", d.Name, d.AuthType, d.StoreType, d.GID, d.UserCount); err != nil {
			return err
		}
	}
	return w.Flush()
}

func cmdDomainShow(paths admin.Paths, name string) error {
	info, err := paths.GetDomain(name)
	if err != nil {
		return err
	}

	fmt.Printf("Domain:    %s\n", info.Name)
	fmt.Printf("Auth:      %s\n", info.AuthType)
	fmt.Printf("Store:     %s\n", info.StoreType)
	fmt.Printf("GID:       %d\n", info.GID)
	fmt.Printf("Users:     %d\n", info.UserCount)

	// Per-domain config.toml details beyond the basics.
	configPath := filepath.Join(paths.Config, name, "config.toml")
	if cfg, err := authdomain.LoadDomainConfig(configPath); err == nil {
		if cfg.DKIM.Selector != "" {
			fmt.Printf("DKIM:      selector=%s key=%s\n", cfg.DKIM.Selector, cfg.DKIM.PrivateKeyPath)
		}
		if cfg.Outbound.Strategy != "" {
			line := "Outbound:  " + cfg.Outbound.Strategy
			if cfg.Outbound.Smarthost != "" {
				line += " via " + cfg.Outbound.Smarthost
			}
			fmt.Println(line)
		}
		if cfg.Limits.MaxSendsPerHour != 0 {
			fmt.Printf("Limits:    max_sends_per_hour=%d\n", cfg.Limits.MaxSendsPerHour)
		}
		if cfg.MaxMessageSize != 0 {
			fmt.Printf("MaxSize:   %d bytes\n", cfg.MaxMessageSize)
		}
		if cfg.RecipientRejection != "" {
			fmt.Printf("RcptRej:   %s\n", cfg.RecipientRejection)
		}
		if len(cfg.Forwards) > 0 {
			fmt.Printf("Forwards:  %d configured (userctl forward list %s)\n", len(cfg.Forwards), name)
		}
	}

	if status, err := paths.DomainKeyStatus(name); err == nil && status.Exists {
		fmt.Printf("DomainKey: x25519 %s (private key: %v)\n", status.Fingerprint, status.HasPrivate)
	}
	return nil
}

func cmdDomainSet(paths admin.Paths, name, key, value string) error {
	if err := paths.SetDomainConfig(name, key, value); err != nil {
		return err
	}
	if value == "" {
		fmt.Printf("Unset %s for %s\n", key, name)
	} else {
		fmt.Printf("Set %s = %s for %s\n", key, value, name)
	}
	return nil
}

// runDomainKeyAction handles `domain key show|create|del <domain>`.
func runDomainKeyAction(args []string, paths admin.Paths, stdin io.Reader) error {
	if len(args) < 2 {
		domainUsage()
		return fmt.Errorf("domain key: expected show|create|del <domain>")
	}
	action := args[0]
	passwordStdin := false
	var names []string
	for _, a := range args[1:] {
		if a == "--password-stdin" {
			passwordStdin = true
		} else {
			names = append(names, a)
		}
	}
	if len(names) != 1 {
		domainUsage()
		return fmt.Errorf("domain key %s: expected <domain>", action)
	}
	name := names[0]

	switch action {
	case "show":
		status, err := paths.DomainKeyStatus(name)
		if err != nil {
			return err
		}
		if !status.Exists {
			fmt.Printf("no domain key for %s\n", name)
			return nil
		}
		fmt.Printf("Algorithm:   x25519\n")
		fmt.Printf("Fingerprint: %s\n", status.Fingerprint)
		fmt.Printf("Private key: %v\n", status.HasPrivate)
		return nil

	case "create":
		password, err := readNewPassword(stdin, passwordStdin)
		if err != nil {
			return err
		}
		fingerprint, err := paths.CreateDomainKeys(name, password)
		if err != nil {
			return err
		}
		fmt.Printf("Generated domain key for %s\nFingerprint: %s\n", name, fingerprint)
		return nil

	case "del":
		if err := paths.DeleteDomainKeys(name); err != nil {
			return err
		}
		fmt.Printf("Deleted domain key for %s\n", name)
		return nil

	default:
		domainUsage()
		return fmt.Errorf("domain key: unknown action %q", action)
	}
}

// runDomainDKIMAction handles `domain dkim create|show <domain>`.
func runDomainDKIMAction(args []string, paths admin.Paths) error {
	if len(args) < 2 {
		domainUsage()
		return fmt.Errorf("domain dkim: expected create|show <domain>")
	}
	action := args[0]

	selector := ""
	force := false
	var names []string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--selector":
			if i+1 >= len(rest) {
				domainUsage()
				return fmt.Errorf("domain dkim: --selector requires a value")
			}
			i++
			selector = rest[i]
		case "--force":
			force = true
		default:
			names = append(names, rest[i])
		}
	}
	if len(names) != 1 {
		domainUsage()
		return fmt.Errorf("domain dkim %s: expected <domain>", action)
	}
	name := names[0]

	switch action {
	case "create":
		rec, err := paths.CreateDKIMKey(name, selector, force)
		if err != nil {
			return err
		}
		fmt.Printf("Generated DKIM key for %s\n", name)
		printDKIMRecord(rec)
		return nil

	case "show":
		rec, err := paths.DKIMStatus(name)
		if err != nil {
			return err
		}
		printDKIMRecord(rec)
		return nil

	default:
		domainUsage()
		return fmt.Errorf("domain dkim: unknown action %q", action)
	}
}

// printDKIMRecord prints the key location and the DNS TXT record, including
// a zone-file line ready to paste.
func printDKIMRecord(rec *admin.DKIMRecord) {
	fmt.Printf("Selector:    %s\n", rec.Selector)
	fmt.Printf("Private key: %s\n", rec.KeyPath)
	fmt.Printf("DNS record:  %s TXT\n", rec.DNSName)
	fmt.Printf("  %s\n", rec.DNSValue)
	fmt.Printf("Zone file line:\n")
	fmt.Printf("  %s. IN TXT %q\n", rec.DNSName, rec.DNSValue)
}

func domainUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  userctl domain create <domain>                    create domain (allocates gid)
  userctl domain del    <domain> [--force]          delete domain config (--force if users exist;
                                                    mail data is retained)
  userctl domain list                               list domains
  userctl domain show   <domain>                    show domain configuration
  userctl domain set    <domain> <key> [<value>]    set a config key (omit value to unset)
  userctl domain key    show   <domain>             show domain encryption key
  userctl domain key    create <domain> [--password-stdin]
  userctl domain key    del    <domain>
  userctl domain fix    <domain> | --all            allocate any missing gid/uids, then repair
                                                    data-dir ownership/modes per the security
                                                    model (run as root to apply uid:gid)
  userctl domain dkim   create <domain> [--selector <s>] [--force]
                                                    generate Ed25519 DKIM key and print
                                                    the DNS TXT record (default selector
                                                    is date-stamped, e.g. d202606)
  userctl domain dkim   show   <domain>             show selector and DNS TXT record
  userctl domain dns    <domain> [--hostname <h>] [--ip <i>]
                                                    check MX/SPF/DKIM/DMARC/PTR against
                                                    public DNS (hostname/IP fall back to
                                                    domain dns.* config, then [dns] or
                                                    smtpd.hostname in the server config)

Config keys for domain set:
  %s
`, strings.Join(admin.DomainConfigKeys(), "\n  "))
}
