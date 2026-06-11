package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/infodancer/maildancer/auth/domain"
)

// runForwardSubcommand handles the `forward` subcommand and its actions:
//
//	userctl [--domains <path>] forward list <domain>
//	userctl [--domains <path>] forward set  <localpart@domain> <target>
//	userctl [--domains <path>] forward del  <localpart@domain>
//
// Forwards are written to the domain's config.toml [forwards] table -- the file
// the forwarding chain actually reads. Forwarding is strictly 1:1: `set` rejects
// a multi-target value. Per-user fan-out belongs in sieve, not here.
func runForwardSubcommand(args []string, domainsPath string) error {
	if len(args) < 1 {
		forwardUsage()
		return fmt.Errorf("forward: missing action")
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case "list":
		if len(rest) != 1 {
			forwardUsage()
			return fmt.Errorf("forward list: expected <domain>")
		}
		return cmdForwardList(domainsPath, rest[0])

	case "set":
		if len(rest) != 2 {
			forwardUsage()
			return fmt.Errorf("forward set: expected <localpart@domain> <target>")
		}
		localpart, domainName, err := splitAddress(rest[0])
		if err != nil {
			return err
		}
		return cmdForwardSet(domainsPath, domainName, localpart, rest[1])

	case "del":
		if len(rest) != 1 {
			forwardUsage()
			return fmt.Errorf("forward del: expected <localpart@domain>")
		}
		localpart, domainName, err := splitAddress(rest[0])
		if err != nil {
			return err
		}
		return cmdForwardDel(domainsPath, domainName, localpart)

	default:
		forwardUsage()
		return fmt.Errorf("forward: unknown action %q", action)
	}
}

// splitAddress splits localpart@domain. The localpart "*" (catchall) is allowed.
func splitAddress(address string) (localpart, domainName string, err error) {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid address %q: expected localpart@domain (use *@domain for the catchall)", address)
	}
	return parts[0], parts[1], nil
}

func cmdForwardList(domainsPath, domainName string) error {
	fwds, err := domain.ListDomainForwards(domainsPath, domainName)
	if err != nil {
		return err
	}
	if len(fwds) == 0 {
		fmt.Printf("no forwards configured for %s\n", domainName)
		return nil
	}

	keys := make([]string, 0, len(fwds))
	for k := range fwds {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "LOCALPART\tTARGET"); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", k, fwds[k]); err != nil {
			return err
		}
	}
	return w.Flush()
}

func cmdForwardSet(domainsPath, domainName, localpart, target string) error {
	if err := domain.SetDomainForward(domainsPath, domainName, localpart, target); err != nil {
		return err
	}
	fmt.Printf("Set forward %s@%s -> %s\n", localpart, domainName, strings.ToLower(strings.TrimSpace(target)))
	return nil
}

func cmdForwardDel(domainsPath, domainName, localpart string) error {
	removed, err := domain.DeleteDomainForward(domainsPath, domainName, localpart)
	if err != nil {
		return err
	}
	if !removed {
		fmt.Printf("no forward for %s@%s\n", localpart, domainName)
		return nil
	}
	fmt.Printf("Deleted forward %s@%s\n", localpart, domainName)
	return nil
}

func forwardUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  userctl [--domains <path>] forward list <domain>
  userctl [--domains <path>] forward set  <localpart@domain> <target>
  userctl [--domains <path>] forward del  <localpart@domain>

Forwarding is 1:1 -- set rejects more than one target. Use *@domain for the
catchall. Per-user fan-out is configured via sieve, not here.`)
}
