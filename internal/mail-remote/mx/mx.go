// Package mx resolves mail exchange hosts for a domain.
package mx

import (
	"fmt"
	"net"
	"sort"
)

// Resolver looks up MX and A/AAAA records. The default uses net.Lookup*;
// tests can substitute a fake.
type Resolver interface {
	LookupMX(domain string) ([]*net.MX, error)
	LookupHost(domain string) ([]string, error)
}

// NetResolver wraps the standard library DNS functions.
type NetResolver struct{}

func (NetResolver) LookupMX(domain string) ([]*net.MX, error) {
	return net.LookupMX(domain)
}

func (NetResolver) LookupHost(domain string) ([]string, error) {
	return net.LookupHost(domain)
}

// Host is a resolved mail exchange target with its SMTP port.
type Host struct {
	Name string
	Port string // typically "25"
}

func (h Host) Addr() string { return net.JoinHostPort(h.Name, h.Port) }

// PermanentError indicates a condition where retrying will not help
// (e.g. null MX, NXDOMAIN on both MX and A).
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Lookup returns mail exchange hosts for domain, ordered by MX priority.
//
// Resolution follows RFC 5321 §5:
//  1. Look up MX records.
//  2. If a null MX exists (RFC 7505: "." at preference 0), return a permanent error.
//  3. Otherwise return MX hosts sorted by preference (lowest first).
//  4. If no MX records exist, fall back to A/AAAA for the domain itself.
//  5. If neither MX nor A/AAAA exist, return a permanent error.
func Lookup(r Resolver, domain string) ([]Host, error) {
	mxs, mxErr := r.LookupMX(domain)
	if mxErr == nil && len(mxs) > 0 {
		// Check for null MX (RFC 7505): single MX with host "." at pref 0.
		if len(mxs) == 1 && mxs[0].Pref == 0 && (mxs[0].Host == "." || mxs[0].Host == "") {
			return nil, &PermanentError{Err: fmt.Errorf("domain %s publishes null MX (RFC 7505)", domain)}
		}

		sort.Slice(mxs, func(i, j int) bool {
			return mxs[i].Pref < mxs[j].Pref
		})

		hosts := make([]Host, 0, len(mxs))
		for _, mx := range mxs {
			// net.LookupMX returns FQDN with trailing dot; strip it.
			name := mx.Host
			if len(name) > 0 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}
			if name == "" {
				continue
			}
			hosts = append(hosts, Host{Name: name, Port: "25"})
		}
		if len(hosts) > 0 {
			return hosts, nil
		}
	}

	// No usable MX — fall back to A/AAAA on the domain itself.
	addrs, aErr := r.LookupHost(domain)
	if aErr != nil || len(addrs) == 0 {
		// Classify: if MX lookup also failed, this is likely NXDOMAIN.
		return nil, &PermanentError{
			Err: fmt.Errorf("no MX or A/AAAA records for %s (mx: %v, a: %v)", domain, mxErr, aErr),
		}
	}

	return []Host{{Name: domain, Port: "25"}}, nil
}
