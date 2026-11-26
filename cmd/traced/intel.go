package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/rep"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/ui"
	"github.com/PalMeany/traced-cli/internal/whois"
)

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// traced feeds [status] | traced feeds update [name…] [--force]
func cmdFeeds(args []string) error {
	o := newOpts("feeds")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	sub := "status"
	if len(pos) > 0 {
		sub, pos = pos[0], pos[1:]
	}
	switch sub {
	case "status", "ls", "list":
		if o.jsonOut {
			return printJSON(feeds.Stat())
		}
		ui.Feeds(os.Stdout, feeds.Stat())
		return nil
	case "update", "up", "refresh":
		ctx, cancel := signalCtx()
		defer cancel()
		if !o.jsonOut {
			fmt.Printf("%s %s\n", ui.C("\x1b[1m", "updating feeds"), ui.C("\x1b[90m", "→ "+feeds.Dir()))
		}
		t0 := time.Now()
		var ixpErr error
		var ixpN int
		var wg sync.WaitGroup
		if len(pos) == 0 {
			// the IXP prefix table lives in the same cache; refresh it weekly too
			if src, _ := geo.IXPSource(); o.force || src == "builtin" || ixpStale() {
				wg.Add(1)
				go func() { defer wg.Done(); ixpN, ixpErr = geo.UpdateIXP(ctx) }()
			}
		}
		rs, err := feeds.UpdateAll(ctx, pos, o.force)
		wg.Wait()
		if err != nil {
			return err
		}
		if o.jsonOut {
			return printJSON(rs)
		}
		ui.FeedResults(os.Stdout, rs)
		if ixpN > 0 {
			fmt.Printf("  %s %s %d prefixes\n", ui.C("\x1b[32m", "✓"), ui.Pad("ixp-prefixes", 17), ixpN)
		} else if ixpErr != nil {
			fmt.Printf("  %s %s %s\n", ui.C("\x1b[31m", "✗"), ui.Pad("ixp-prefixes", 17), ixpErr)
		}
		fmt.Printf("%s\n", ui.C("\x1b[90m", "done in "+time.Since(t0).Round(100*time.Millisecond).String()))
		failed := 0
		for _, r := range rs {
			if r.Err != nil {
				failed++
			}
		}
		if failed == len(rs) && len(rs) > 0 {
			return errors.New("every feed failed to update")
		}
		return nil
	}
	return fmt.Errorf("usage: traced feeds [status] | traced feeds update [%s] [--force]", "name…")
}

func ixpStale() bool {
	st, err := os.Stat(ixpFile())
	return err != nil || time.Since(st.ModTime()) > 7*24*time.Hour
}

// traced asn <ASN|IP|domain> [--json] [--prefixes] [--no-rep]
func cmdASN(args []string) error {
	o := newOpts("asn")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced asn <AS13335|IP|domain> [--prefixes] [--no-rep] [--json]")
	}
	ctx, cancel := signalCtx()
	defer cancel()
	opt := asn.Full
	r, err := asn.Lookup(ctx, pos[0], opt)
	if err != nil {
		return err
	}
	var rp *rep.Report
	if !o.noRep {
		ro := rep.DefaultOptions()
		if r.Routing != nil {
			ro.PrefixesV4, ro.PrefixesV6 = r.Routing.V4, r.Routing.V6
		}
		rp = rep.CheckASN(ctx, r.ASN, ro)
	}
	if o.jsonOut {
		return printJSON(struct {
			*asn.Report
			Reputation *rep.Report `json:"reputation,omitempty"`
		}{r, rp})
	}
	ui.ASN(os.Stdout, r, o.prefixes)
	if rp != nil {
		ui.Rep(os.Stdout, rp)
	}
	return nil
}

// traced bgp <prefix|ip|ASN|domain> [--json]
func cmdBGP(args []string) error {
	o := newOpts("bgp")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced bgp <prefix|ip|AS13335|domain> [--json]")
	}
	ctx, cancel := signalCtx()
	defer cancel()
	q := pos[0]
	// Direct CIDR prefix?
	if _, err := netip.ParsePrefix(q); err == nil {
		pb, err := asn.LookupPrefix(ctx, q, o.offline)
		if err != nil {
			return err
		}
		if o.jsonOut {
			return printJSON(pb)
		}
		ui.PrefixBGP(os.Stdout, pb)
		return nil
	}
	// Resolve ASN / IP / domain
	t, err := asn.Resolve(ctx, q)
	if err != nil {
		return err
	}
	var pb *asn.PrefixBGP
	if t.Prefix != "" {
		pb, _ = asn.LookupPrefix(ctx, t.Prefix, o.offline)
	}
	r := asn.Profile(ctx, t.ASN, asn.Options{Neighbours: true, Visibility: true, History: true, Prefixes: true, NoNetwork: o.offline})
	r.Query, r.IP, r.Prefix = q, t.IP, t.Prefix
	if o.jsonOut {
		return printJSON(struct {
			Prefix *asn.PrefixBGP `json:"prefix,omitempty"`
			ASN    *asn.Report    `json:"asn,omitempty"`
		}{pb, r})
	}
	if pb != nil {
		ui.PrefixBGP(os.Stdout, pb)
	}
	ui.ASN(os.Stdout, r, o.prefixes)
	return nil
}

// traced mtu <target> [-p PORT] [-4|-6] [--iface IF] [--json]
func cmdMTU(args []string) error {
	o := newOpts("mtu")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced mtu <target> [-p PORT] [-4|-6] [--json]")
	}
	ctx, cancel := signalCtx()
	defer cancel()
	to := o.traceOptions(pos[0])
	_, _, note := app.ResolveInterface(&to)
	if note != "" && !o.jsonOut {
		ui.Note(os.Stdout, note)
	}
	port := o.port
	if port <= 0 {
		port = 443
	}
	res, err := trace.ProbeMTU(ctx, trace.MTUOptions{
		Target: pos[0], Port: port, IPv4: o.v4, IPv6: o.v6,
		Timeout: o.timeout, Interface: to.Interface,
	})
	if err != nil {
		return err
	}
	if o.jsonOut {
		return printJSON(res)
	}
	ui.MTU(os.Stdout, res)
	return nil
}

// traced nat [target] [--iface IF] [--json]
func cmdNAT(args []string) error {
	o := newOpts("nat")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	target := "1.1.1.1"
	if len(pos) > 0 {
		target = pos[0]
	}
	ctx, cancel := signalCtx()
	defer cancel()
	to := o.traceOptions(target)
	if to.MaxTTL > 8 {
		to.MaxTTL = 8
	}
	if to.Probes > 1 {
		to.Probes = 1
	}
	_, _, note := app.ResolveInterface(&to)
	if note != "" && !o.jsonOut {
		ui.Note(os.Stdout, note)
	}
	r, _ := trace.Run(ctx, to, nil)
	var hops []trace.Hop
	tip := target
	if r != nil {
		hops = r.Hops
		if r.TargetIP != "" {
			tip = r.TargetIP
		}
	}
	nat := trace.DetectNAT(ctx, tip, hops, o.offline)
	if o.jsonOut {
		return printJSON(nat)
	}
	ui.NAT(os.Stdout, nat)
	return nil
}

// traced rep <IP|ASN|domain> [--json] [--no-dnsbl]
func cmdRep(args []string) error {
	o := newOpts("rep")
	pos, err := o.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: traced rep <IP|AS13335|domain> [--no-dnsbl] [--json]")
	}
	ctx, cancel := signalCtx()
	defer cancel()
	ro := rep.DefaultOptions()
	if o.noDNSBL {
		ro.DNSBL = false
	}
	r, err := rep.Check(ctx, pos[0], ro)
	if err != nil {
		return err
	}
	if o.jsonOut {
		return printJSON(r)
	}
	ui.Rep(os.Stdout, r)
	return nil
}

// WhoisPlus is `traced whois` with reputation and AS profiles of the addresses.
type WhoisPlus struct {
	*whois.Report
	Reputation []*rep.Report `json:"reputation,omitempty"`
	ASNs       []*asn.Report `json:"asns,omitempty"`
}

// enrichWhois adds reputation and AS profiles for the report's addresses.
func enrichWhois(ctx context.Context, w *whois.Report, withRep, withASN, dnsbl bool) *WhoisPlus {
	out := &WhoisPlus{Report: w}
	if w == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	seen := map[int]bool{}
	reps := make([]*rep.Report, len(w.IPs))
	for i, ip := range w.IPs {
		a, err := netip.ParseAddr(ip.IP)
		if err != nil {
			continue
		}
		if withRep {
			wg.Add(1)
			go func(i int, a netip.Addr) {
				defer wg.Done()
				ro := rep.DefaultOptions()
				ro.WithASN, ro.DNSBL = false, dnsbl
				reps[i] = rep.CheckIP(ctx, a, ro)
			}(i, a)
		}
	}
	if withASN {
		for _, ip := range w.IPs {
			n := ip.ASN
			if n == 0 {
				if a, err := whois.LookupASN(ctx, net.ParseIP(ip.IP)); err == nil && a != nil {
					n = a.ASN
				}
			}
			if n == 0 || seen[n] {
				continue
			}
			seen[n] = true
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				r := asn.Profile(ctx, n, asn.Options{Timeout: 12 * time.Second})
				mu.Lock()
				out.ASNs = append(out.ASNs, r)
				mu.Unlock()
			}(n)
		}
	}
	wg.Wait()
	for _, r := range reps {
		if r != nil {
			out.Reputation = append(out.Reputation, r)
		}
	}
	return out
}

func ixpFile() string { return cache.File("peeringdb-ixp.json") }
