package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/trace"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

type opts struct {
	fs *flag.FlagSet

	tcp, udp, icmp, v4, v6 bool
	port                   int
	sni, controlSNI        string
	web, jsonOut, noGeo    bool
	mmdb                   string
	geofeeds               multiFlag
	offline                bool
	iface                  string
	probes, maxTTL         int
	timeout                time.Duration
	paris, noSave, noWhois bool
	numeric                bool
	origin                 string
	listen                 string
	noOpen                 bool
	noScan                 bool
	interval, sendGap      time.Duration
	limit                  int
}

func newOpts(name string) *opts {
	o := &opts{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	f := o.fs
	f.BoolVar(&o.tcp, "T", false, "TCP SYN probes (default port 443)")
	f.BoolVar(&o.udp, "U", false, "UDP probes")
	f.BoolVar(&o.icmp, "I", false, "ICMP echo probes (default)")
	f.BoolVar(&o.v4, "4", false, "force IPv4")
	f.BoolVar(&o.v6, "6", false, "force IPv6")
	f.IntVar(&o.port, "p", 0, "destination port (tcp: 443, udp: 33434)")
	f.StringVar(&o.sni, "sni", "", "after the trace, probe TLS with this SNI")
	f.StringVar(&o.controlSNI, "control-sni", "example.com", "harmless SNI used for comparison")
	f.BoolVar(&o.web, "web", false, "open the result on the local web map")
	f.BoolVar(&o.jsonOut, "json", false, "print JSON")
	f.BoolVar(&o.noGeo, "no-geo", false, "skip geolocation / ASN lookups")
	f.StringVar(&o.mmdb, "mmdb", os.Getenv("TRACED_MMDB"), "local GeoLite2/DB-IP city .mmdb")
	f.Var(&o.geofeeds, "geofeed", "extra RFC 8805 geofeed CSV file or directory (repeatable)")
	f.BoolVar(&o.offline, "offline", false, "geo from local sources only (rDNS, IXP table, local geofeeds, mmdb)")
	def := os.Getenv("TRACED_IFACE")
	if def == "" {
		def = "auto"
	}
	f.StringVar(&o.iface, "iface", def, "bind probes to an interface: auto (bypass VPN/TUN), none, en0 …")
	f.IntVar(&o.probes, "q", 3, "probes per hop (ECMP discovery)")
	f.IntVar(&o.maxTTL, "m", 30, "max TTL")
	f.DurationVar(&o.timeout, "w", 2*time.Second, "probe timeout")
	f.BoolVar(&o.paris, "paris", false, "keep the flow constant (no ECMP spreading)")
	f.BoolVar(&o.noSave, "no-save", false, "do not store the trace in history")
	f.BoolVar(&o.noWhois, "no-whois", false, "skip WHOIS/RDAP of the target")
	f.BoolVar(&o.numeric, "n", false, "show IPs only (no PTR names)")
	f.StringVar(&o.origin, "origin", os.Getenv("TRACED_ORIGIN"), "your location for RTT physics: \"lat,lon\" or IATA code (msk, fra…)")
	f.StringVar(&o.listen, "listen", "127.0.0.1:7477", "web UI listen address")
	f.BoolVar(&o.noOpen, "no-open", false, "do not open the browser")
	f.BoolVar(&o.noScan, "no-scan", false, "sni: skip the TTL scan")
	f.DurationVar(&o.interval, "i", time.Second, "mtr: interval between rounds")
	f.DurationVar(&o.sendGap, "gap", 0, "pause between probe packets (default 12ms; raise it if an ISP polices ICMP)")
	f.IntVar(&o.limit, "limit", 20, "history: number of entries")
	f.Usage = func() {}
	return o
}

// parse accepts flags anywhere (before or after positionals) and long --flags.
func (o *opts) parse(args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if j := strings.Index(name, "="); j >= 0 {
				flags = append(flags, "-"+name)
				continue
			}
			fl := o.fs.Lookup(name)
			if fl == nil {
				return nil, fmt.Errorf("unknown flag %s", a)
			}
			if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
				flags = append(flags, "-"+name)
				continue
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("flag %s needs a value", a)
			}
			flags = append(flags, "-"+name, args[i+1])
			i++
			continue
		}
		pos = append(pos, a)
	}
	if err := o.fs.Parse(flags); err != nil {
		return nil, err
	}
	return pos, nil
}

func (o *opts) traceOptions(target string) trace.Options {
	p := trace.ICMP
	switch {
	case o.tcp:
		p = trace.TCP
	case o.udp:
		p = trace.UDP
	}
	return trace.Options{Target: target, Protocol: p, Port: o.port, IPv4: o.v4, IPv6: o.v6, MaxTTL: o.maxTTL,
		Probes: o.probes, Timeout: o.timeout, Paris: o.paris, Interface: o.iface, Interval: o.sendGap}
}

func (o *opts) geoOptions() (geo.Options, error) {
	g := geo.Options{Offline: o.offline, MMDB: o.mmdb, IPInfoToken: os.Getenv("TRACED_IPINFO_TOKEN"), Geofeeds: o.geofeeds}
	if h, err := os.UserHomeDir(); err == nil {
		g.Geofeeds = append(g.Geofeeds, h+"/.config/traced/geofeeds")
	}
	if o.origin != "" {
		pt, err := parseOrigin(o.origin)
		if err != nil {
			return g, err
		}
		g.Origin = pt
	}
	return g, nil
}

func parseOrigin(s string) (*geo.Point, error) {
	if p := strings.Split(s, ","); len(p) == 2 {
		lat, e1 := strconv.ParseFloat(strings.TrimSpace(p[0]), 64)
		lon, e2 := strconv.ParseFloat(strings.TrimSpace(p[1]), 64)
		if e1 == nil && e2 == nil {
			return &geo.Point{Lat: lat, Lon: lon}, nil
		}
	}
	if c := geo.LookupCity(s); c != nil {
		return &geo.Point{Lat: c.Lat, Lon: c.Lon}, nil
	}
	return nil, fmt.Errorf("bad --origin %q (use \"lat,lon\" or a city/IATA code)", s)
}
