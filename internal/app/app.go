// Package app glues the trace engine, the geo resolver, WHOIS and storage
// together; it is shared by the CLI, the MTR view and the web UI.
package app

import (
	"context"
	"fmt"
	"github.com/PalMeany/traced-cli/internal/backbone"
	"net"
	"strings"
	"sync"

	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/store"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/whois"
)

// Version of traced.
var Version = "1.4.0"

// Config describes one trace job.
type Config struct {
	Trace      trace.Options
	Geo        bool
	GeoOpts    geo.Options
	Whois      bool   // attach WHOIS/RDAP + DNS of the target
	SNI        string // run an SNI probe with this server name after the trace
	ControlSNI string
	MTU        bool // run ICMP+TCP Path MTU probe (20->5->1 staircase)
	NoNAT      bool // skip NAT/CGNAT detection
	Save       bool
	Tunnel     string // set when the caller already resolved Interface="auto"
	ASN        bool   // profile every AS on the path (rank, traffic, PoPs, reputation)
}

// Extra is attached to Result.Extra.
type Extra struct {
	Whois     *whois.Report             `json:"whois,omitempty"`
	SNI       *trace.SNIResult          `json:"sni,omitempty"`
	MTU       *trace.MTUResult          `json:"mtu,omitempty"`
	NAT       *trace.NATResult          `json:"nat,omitempty"`
	ASNs      map[string]*asn.Brief     `json:"asns,omitempty"`       // AS profiles keyed by number
	PrefixBGP map[string]*asn.PrefixBGP `json:"prefix_bgp,omitempty"` // BGP upstreams & history per hop prefix
	IXPs      []RouteIXP                `json:"ixps,omitempty"`       // IXPs automatically detected on the path
	Cables    []SegmentCables           `json:"cables,omitempty"`     // submarine cable hints (heuristic)
	Backbones []backbone.Hint           `json:"backbones,omitempty"`  // terrestrial backbones of ASes on the path
	Interface string                    `json:"interface,omitempty"`
	Tunnel    string                    `json:"tunnel,omitempty"`
	Notes     []string                  `json:"notes,omitempty"`
}

// ResolveInterface handles the "auto" interface mode. It returns the
// interface to use and a human note (may be empty).
func ResolveInterface(o *trace.Options) (string, string, string) {
	if o.Interface != "auto" {
		if o.Interface == "none" {
			o.Interface = ""
		}
		return o.Interface, "", ""
	}
	o.Interface = ""
	dst, err := trace.ResolveTarget(o.Target, o.IPv4, o.IPv6)
	if err != nil {
		return "", "", ""
	}
	ifn, tun := trace.AutoInterface(dst)
	if ifn != "" {
		o.Interface = ifn
		return ifn, tun, fmt.Sprintf("route to %s goes through tunnel %s — bypassing it via %s (use --iface none to trace inside the tunnel)", dst, tun, ifn)
	}
	if tun != "" {
		return "", tun, fmt.Sprintf("route goes through tunnel %s and no physical default route was found; hops may be hidden", tun)
	}
	return "", "", ""
}

// IsDomain reports whether target looks like a hostname rather than an IP.
func IsDomain(t string) bool {
	return net.ParseIP(t) == nil && strings.Contains(t, ".")
}

// Run executes the job and streams enriched events in hop order.
func Run(ctx context.Context, cfg Config, emit func(trace.Event)) (*trace.Result, error) {
	if emit == nil {
		emit = func(trace.Event) {}
	}
	ex := &Extra{}
	ifn, tun, note := ResolveInterface(&cfg.Trace)
	if tun == "" {
		tun = cfg.Tunnel
	}
	ex.Interface, ex.Tunnel = ifn, tun
	if note != "" {
		ex.Notes = append(ex.Notes, note)
		emit(trace.Event{Type: "note", Note: note})
	}

	var res *geo.Resolver
	if cfg.Geo {
		var err error
		res, err = geo.New(cfg.GeoOpts)
		if err != nil {
			return nil, err
		}
		defer res.Close()
	}

	// WHOIS/DNS of the target in parallel with the trace
	var wwg sync.WaitGroup
	if cfg.Whois && !cfg.GeoOpts.Offline {
		wwg.Add(1)
		go func() {
			defer wwg.Done()
			rep := whois.Lookup(ctx, cfg.Trace.Target)
			ex.Whois = rep
			emit(trace.Event{Type: "whois", Data: rep})
		}()
	}

	// enrichment pipeline: hops arrive in order, geo data is gathered per hop
	// concurrently, then emitted in order after path validation.
	type slot struct {
		hop  trace.Hop
		done chan struct{}
	}
	var (
		mu    sync.Mutex
		slots []*slot
		data  = map[string]*geo.IPData{}
	)
	var enr *enricher
	if cfg.ASN && cfg.Geo && !cfg.GeoOpts.Offline {
		enr = newEnricher(ctx, emit)
	}
	out := make(chan *slot, 64)
	var pwg sync.WaitGroup
	pwg.Add(1)
	var hops []trace.Hop
	go func() {
		defer pwg.Done()
		for s := range out {
			<-s.done
			hops = append(hops, s.hop)
			if res != nil {
				mu.Lock()
				geo.Validate(hops, data, res.Origin())
				mu.Unlock()
			}
			h := hops[len(hops)-1]
			emit(trace.Event{Type: "hop", Hop: &h})
			if enr != nil {
				enr.add(&h)
			}
		}
	}()
	var start *trace.Result
	r, err := trace.Run(ctx, cfg.Trace, func(e trace.Event) {
		switch e.Type {
		case "start":
			start = e.Result
			emit(e)
		case "hop":
			s := &slot{hop: *e.Hop, done: make(chan struct{})}
			mu.Lock()
			slots = append(slots, s)
			mu.Unlock()
			if res == nil {
				close(s.done)
			} else {
				var ips []string
				for _, rs := range e.Hop.Responders {
					ips = append(ips, rs.IP)
				}
				go func() {
					d := res.Gather(ctx, ips)
					mu.Lock()
					for k, v := range d {
						data[k] = v
					}
					mu.Unlock()
					close(s.done)
				}()
			}
			out <- s
		}
	})
	close(out)
	pwg.Wait()
	_ = start
	if r == nil {
		return nil, err
	}
	r.Hops = hops

	if cfg.SNI != "" && ctx.Err() == nil {
		port := cfg.Trace.Port
		if cfg.Trace.Protocol != trace.TCP || port == 0 {
			port = 443
		}
		emit(trace.Event{Type: "note", Note: "SNI probe: " + cfg.SNI})
		sr, serr := trace.ProbeSNI(ctx, trace.SNIOptions{
			Host: r.TargetIP, SNI: cfg.SNI, ControlSNI: cfg.ControlSNI, Port: port,
			IPv6: r.IPv6, Interface: cfg.Trace.Interface,
		}, func(st trace.SNIStep) {
			s := st
			emit(trace.Event{Type: "sni-step", Step: &s})
		})
		if serr != nil {
			ex.Notes = append(ex.Notes, "sni: "+serr.Error())
		} else {
			ex.SNI = sr
			emit(trace.Event{Type: "sni", Data: sr})
		}
	}
	if cfg.MTU && ctx.Err() == nil {
		port := cfg.Trace.Port
		if cfg.Trace.Protocol != trace.TCP || port == 0 {
			port = 443
		}
		emit(trace.Event{Type: "note", Note: "MTU probe (ICMP DF + TCP MSS/PMTUD, 20→5→1)…"})
		mr, merr := trace.ProbeMTU(ctx, trace.MTUOptions{
			Target: r.TargetIP, Port: port, IPv6: r.IPv6, IPv4: !r.IPv6,
			Interface: cfg.Trace.Interface, Hops: r.Hops,
		})
		if merr != nil {
			ex.Notes = append(ex.Notes, "mtu: "+merr.Error())
		} else {
			ex.MTU = mr
			emit(trace.Event{Type: "mtu", Data: mr})
		}
	}
	if !cfg.NoNAT && ctx.Err() == nil {
		ex.NAT = trace.DetectNAT(ctx, r.TargetIP, r.Hops, cfg.GeoOpts.Offline)
		if ex.NAT != nil {
			emit(trace.Event{Type: "nat", Data: ex.NAT})
		}
	}
	wwg.Wait()
	if enr != nil {
		ex.ASNs, ex.PrefixBGP = enr.finish(r.Hops)
		if len(ex.ASNs) > 0 {
			emit(trace.Event{Type: "asns", Data: ex.ASNs})
		}
		if len(ex.PrefixBGP) > 0 {
			emit(trace.Event{Type: "prefix-bgp", Data: ex.PrefixBGP})
		}
	}
	if cfg.Geo {
		ex.IXPs = RouteIXPs(r.Hops)
		ex.Cables = CableHints(feeds.CablesLocal(), r.Hops)
		ex.Backbones = BackboneHints(backbone.All(true), r.Hops)
	}
	r.Extra = ex
	if cfg.Save {
		if serr := store.Default().Save(r); serr != nil {
			ex.Notes = append(ex.Notes, "save: "+serr.Error())
		}
	}
	emit(trace.Event{Type: "done", Result: r})
	return r, err
}

// InfoOf decodes the geo info of a responder (live or loaded from JSON).
func InfoOf(r *trace.Responder) *geo.Info {
	if r == nil || r.Geo == nil {
		return nil
	}
	if i, ok := r.Geo.(*geo.Info); ok {
		return i
	}
	var i geo.Info
	if remarshal(r.Geo, &i) == nil {
		return &i
	}
	return nil
}

// ASOf decodes the AS info of a responder.
func ASOf(r *trace.Responder) *whois.ASInfo {
	if r == nil || r.Network == nil {
		return nil
	}
	if a, ok := r.Network.(*whois.ASInfo); ok {
		return a
	}
	var a whois.ASInfo
	if remarshal(r.Network, &a) == nil && a.ASN != 0 {
		return &a
	}
	return nil
}

// ExtraOf decodes Result.Extra.
func ExtraOf(r *trace.Result) *Extra {
	if r == nil || r.Extra == nil {
		return nil
	}
	if e, ok := r.Extra.(*Extra); ok {
		return e
	}
	var e Extra
	if remarshal(r.Extra, &e) == nil {
		return &e
	}
	return nil
}
