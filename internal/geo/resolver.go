// Package geo locates traceroute hops using several independent sources
// (rDNS/IATA parsing, IXP prefixes, RFC 8805 geofeeds, RIPE IPmap, GeoIP)
// and validates the answers against the speed of light in fibre.
package geo

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/whois"
)

// Info is the final location verdict for one responder.
type Info struct {
	City          string      `json:"city,omitempty"`
	Region        string      `json:"region,omitempty"`
	Country       string      `json:"country,omitempty"`
	Lat           float64     `json:"lat,omitempty"`
	Lon           float64     `json:"lon,omitempty"`
	Located       bool        `json:"located"`
	Source        string      `json:"source,omitempty"`
	Priority      int         `json:"priority,omitempty"`
	Confidence    float64     `json:"confidence,omitempty"`
	Private       bool        `json:"private,omitempty"`
	IXP           *IXP        `json:"ixp,omitempty"`
	Backbone      *Backbone   `json:"backbone,omitempty"`
	RTTAnomaly    bool        `json:"rtt_anomaly,omitempty"`
	Anomaly       string      `json:"anomaly,omitempty"`
	Geofeed       string      `json:"geofeed,omitempty"`
	Discrepancies []string    `json:"discrepancies,omitempty"`
	Candidates    []Candidate `json:"candidates,omitempty"`
}

// Label is a short human readable location.
func (i *Info) Label() string {
	if i == nil {
		return ""
	}
	if i.Private {
		return "private"
	}
	if i.City != "" && i.Country != "" {
		return i.City + ", " + i.Country
	}
	if i.Country != "" {
		return i.Country
	}
	return i.City
}

// Options configure the resolver.
type Options struct {
	Offline     bool // only local sources (rDNS parsing, IXP table, local geofeeds, mmdb)
	NoIPMap     bool
	NoGeoIP     bool
	NoGeofeed   bool
	MMDB        string   // path to a local .mmdb
	IPInfoToken string   // TRACED_IPINFO_TOKEN
	Geofeeds    []string // local geofeed CSV files/dirs
	Origin      *Point   // optional known source location
	Parallel    int
}

// Resolver resolves and validates hop locations.
type Resolver struct {
	o     Options
	mmdb  *MMDB
	local []*Geofeed
}

// New creates a resolver.
func New(o Options) (*Resolver, error) {
	if o.Parallel <= 0 {
		o.Parallel = 12
	}
	r := &Resolver{o: o}
	if o.MMDB != "" {
		m, err := OpenMMDB(o.MMDB)
		if err != nil {
			return nil, fmt.Errorf("mmdb: %v", err)
		}
		r.mmdb = m
	}
	r.local = LoadLocalGeofeeds(o.Geofeeds)
	return r, nil
}

// Close releases resources.
func (r *Resolver) Close() { r.mmdb.Close() }

// IsPrivate reports RFC1918/CGNAT/link-local/ULA addresses.
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64/10 CGNAT
			return true
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
	}
	return false
}

// IPData is everything gathered about one address.
type IPData struct {
	host  string
	as    *whois.ASInfo
	cands []Candidate
	ixp   *IXP
	bb    *Backbone
	feed  string
	rir   string // country of the allocation (RDAP/whois, else the ASN's)
	priv  bool
}

// Gather collects candidates from all sources for a set of IPs.
func (r *Resolver) Gather(ctx context.Context, ips []string) map[string]*IPData {
	out := map[string]*IPData{}
	var mu sync.Mutex
	var public []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		d := &IPData{priv: IsPrivate(ip)}
		out[s] = d
		if !d.priv {
			public = append(public, s)
		}
	}
	var geoip map[string]*Candidate
	var wg sync.WaitGroup
	if !r.o.Offline && !r.o.NoGeoIP && r.mmdb == nil && len(public) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := GeoIPBatch(ctx, public, r.o.IPInfoToken)
			mu.Lock()
			geoip = g
			mu.Unlock()
		}()
	}
	sem := make(chan struct{}, r.o.Parallel)
	for _, s := range ips {
		d := out[s]
		ip := net.ParseIP(s)
		wg.Add(1)
		go func(s string, ip net.IP, d *IPData) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d.host = PTR(ctx, s)
			if d.priv {
				return
			}
			var cands []Candidate
			if m := ParseHostname(d.host); m != nil {
				d.bb = m.Backbone
				if m.City != nil && m.Backbone != nil {
					// a location code inside a known carrier's naming scheme is very reliable
					m.Confidence = minF([]float64{m.Confidence + 0.22, 0.88})
				}
				if m.City != nil {
					cands = append(cands, Candidate{Source: SrcRDNS, City: m.City.Name, Country: m.City.Country,
						Lat: m.City.Lat, Lon: m.City.Lon, HasCoords: true, Confidence: m.Confidence,
						Detail: fmt.Sprintf("%s → %s", m.Token, strings.ToUpper(m.City.Code))})
				}
			}
			if x := LookupIXP(ip); x != nil {
				d.ixp = x
				c := Candidate{Source: SrcIXP, City: x.City, Country: x.Country, Confidence: 0.9, Detail: x.Name + " " + x.Prefix}
				if ct := LookupCityIn(x.City, x.Country); ct != nil {
					c.Lat, c.Lon, c.HasCoords, c.City = ct.Lat, ct.Lon, true, ct.Name
				}
				cands = append(cands, c)
			} else if x := LookupIXPByHostname(d.host); x != nil {
				d.ixp = x
				if x.City != "" {
					c := Candidate{Source: SrcIXP, City: x.City, Country: x.Country, Confidence: 0.85, Detail: x.Name + " (rDNS)"}
					if ct := LookupCityIn(x.City, x.Country); ct != nil {
						c.Lat, c.Lon, c.HasCoords, c.City = ct.Lat, ct.Lon, true, ct.Name
					}
					cands = append(cands, c)
				}
			}
			for _, g := range r.local {
				if e := g.Lookup(ip); e != nil {
					cands = append(cands, feedCandidate(e, g.URL, 0.9))
					break
				}
			}
			if r.mmdb != nil {
				if c := r.mmdb.Lookup(ip); c != nil {
					cands = append(cands, *c)
				}
			}
			if !r.o.Offline {
				var iwg sync.WaitGroup
				var imc, iic *Candidate
				if !r.o.NoIPMap {
					iwg.Add(1)
					go func() {
						defer iwg.Done()
						imc, _ = IPMap(ctx, s)
					}()
				}
				if !r.o.NoGeoIP && r.o.IPInfoToken == "" {
					iwg.Add(1)
					go func() {
						defer iwg.Done()
						iic = IPInfoLite(ctx, s, "")
					}()
				}
				d.as, _ = whois.LookupASN(ctx, ip)
				if info, err := whois.LookupIP(ctx, s); err == nil {
					d.rir = strings.ToUpper(info.Country)
					if !r.o.NoGeofeed && info.Geofeed != "" {
						d.feed = info.Geofeed
						if g, err := FetchGeofeed(ctx, info.Geofeed); err == nil {
							if e := g.Lookup(ip); e != nil {
								cands = append(cands, feedCandidate(e, info.Geofeed, 0.85))
							}
						}
					}
				}
				if d.rir == "" && d.as != nil {
					d.rir = strings.ToUpper(d.as.Country)
				}
				iwg.Wait()
				if imc != nil {
					cands = append(cands, *imc)
				}
				if iic != nil {
					cands = append(cands, *iic)
				}
			}
			mu.Lock()
			d.cands = cands
			mu.Unlock()
		}(s, ip, d)
	}
	wg.Wait()
	for s, c := range geoip {
		if d := out[s]; d != nil && c != nil {
			d.cands = append(d.cands, *c)
		}
	}
	// geofeed / IXP entries without coordinates borrow them from a source naming the same city
	for _, d := range out {
		for i := range d.cands {
			c := &d.cands[i]
			if c.HasCoords || c.City == "" {
				continue
			}
			for _, o := range d.cands {
				if o.HasCoords && strings.EqualFold(o.City, c.City) {
					c.Lat, c.Lon, c.HasCoords = o.Lat, o.Lon, true
					break
				}
			}
		}
		d.cands = Reconcile(d.cands, d.rir)
		for i := range d.cands {
			if d.cands[i].Priority == 0 {
				d.cands[i].Priority = SourcePriority(d.cands[i].Source)
			}
		}
		sort.SliceStable(d.cands, func(i, j int) bool {
			diff := d.cands[i].Confidence - d.cands[j].Confidence
			if diff > 0.05 || diff < -0.05 {
				return diff > 0
			}
			if d.cands[i].Priority != d.cands[j].Priority {
				return d.cands[i].Priority < d.cands[j].Priority
			}
			return diff > 0
		})
	}
	return out
}

// weakSources are database-style answers that often carry a company's home
// country rather than where the address actually is.
var weakSources = map[string]bool{SrcIPMap: true, SrcGeoIP: true, SrcMMDB: true}

// Reconcile cross-checks weak candidates against the registry country of the
// allocation (rir). Weak claims (confidence < 0.6: IPmap guesses, GeoIP, mmdb)
// naming another country are demoted. If nothing with coordinates agrees with
// the registry and IPmap supplied a latency radius, the best known city of the
// registry country inside that radius is offered instead — the radius is a
// measurement, the population pick of IPmap's "worlds" engine is not.
func Reconcile(cands []Candidate, rir string) []Candidate {
	if rir == "" || rir == "ZZ" || rir == "EU" {
		return cands
	}
	var area *Area
	for _, c := range cands {
		if c.Area != nil {
			area = c.Area
			break
		}
	}
	agree := false
	for i := range cands {
		c := &cands[i]
		if strings.EqualFold(c.Country, rir) {
			agree = agree || c.HasCoords && area.Contains(c.Lat, c.Lon)
			continue
		}
		if c.Country != "" && c.Confidence < 0.6 && weakSources[c.Source] {
			c.Confidence *= 0.6
			c.Detail = strings.TrimPrefix(c.Detail+"; registry says "+rir, "; ")
		}
	}
	if agree || area == nil {
		return cands
	}
	for _, ct := range allCities { // the table lists the main city of each country first
		if strings.EqualFold(ct.Country, rir) && area.Contains(ct.Lat, ct.Lon) {
			return append(cands, Candidate{Source: SrcRIR, City: ct.Name, Country: ct.Country, Lat: ct.Lat, Lon: ct.Lon,
				HasCoords: true, Confidence: 0.35,
				Detail: fmt.Sprintf("registry country %s, main city inside the %.0f km latency radius", rir, area.RadiusKm)})
		}
	}
	return cands
}

func feedCandidate(e *GeofeedEntry, url string, conf float64) Candidate {
	c := Candidate{Source: SrcGeofeed, City: e.City, Region: e.Region, Country: e.Country, Confidence: conf,
		Detail: e.CIDR + " via " + url}
	if ct := LookupCityIn(e.City, e.Country); ct != nil {
		c.Lat, c.Lon, c.HasCoords = ct.Lat, ct.Lon, true
	}
	if e.City == "" {
		c.Confidence = 0.3 // country-level only
	}
	return c
}

// ResolveHops fills Host / Geo / Network for every responder of the trace and
// runs the RTT physics validation along the path.
func (r *Resolver) ResolveHops(ctx context.Context, hops []trace.Hop) {
	seen := map[string]bool{}
	var ips []string
	for _, h := range hops {
		for _, rs := range h.Responders {
			if !seen[rs.IP] {
				seen[rs.IP] = true
				ips = append(ips, rs.IP)
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	data := r.Gather(ctx, ips)
	Validate(hops, data, r.o.Origin)
}

// Origin returns the configured source location (may be nil).
func (r *Resolver) Origin() *Point {
	return r.o.Origin
}

// Validate picks, for each responder, the most confident candidate that is
// physically possible given the RTTs, flagging contradictions.
func Validate(hops []trace.Hop, data map[string]*IPData, origin *Point) {
	var anchors []Point
	var last *Info
	for hi := range hops {
		for ri := range hops[hi].Responders {
			rs := &hops[hi].Responders[ri]
			d := data[rs.IP]
			if d == nil {
				continue
			}
			rs.Host = d.host
			if d.as != nil {
				rs.Network = d.as
			}
			info := &Info{Private: d.priv, IXP: d.ixp, Backbone: d.bb, Geofeed: d.feed}
			rtt := minF(rs.RTTs)
			cands := append([]Candidate(nil), d.cands...)
			var area *Area
			for _, c := range cands {
				if c.Area != nil {
					area = c.Area
					break
				}
			}
			chosen := -1
			for ci := range cands {
				c := &cands[ci]
				if !c.HasCoords {
					continue
				}
				// the radius is one Atlas probe's view (its own position may be off,
				// or another interface answered): it vetoes only weak claims
				if c.Confidence < 0.6 && !area.Contains(c.Lat, c.Lon) {
					c.Rejected = fmt.Sprintf("%.0f km from %s, outside its %.0f km latency radius",
						DistanceKm(area.Lat, area.Lon, c.Lat, c.Lon), orStr(area.From, "a RIPE Atlas probe"), area.RadiusKm)
					continue
				}
				p := Point{Lat: c.Lat, Lon: c.Lon, RTT: rtt}
				if ok, dist := FeasibleFromOrigin(origin, p); !ok {
					c.Rejected = "from origin: " + violation(dist, rtt)
					continue
				}
				bad := ""
				for _, a := range anchors {
					if ok, dist := Feasible(a, p); !ok {
						bad = fmt.Sprintf("%.0f km from %s (seen at %.1f ms) — %.1f + %.1f ms RTT allow at most %.0f km",
							dist, a.Name, a.RTT, a.RTT, rtt, MaxKm(a.RTT)+MaxKm(rtt))
						break
					}
				}
				if bad != "" {
					c.Rejected = bad
					continue
				}
				chosen = ci
				break
			}
			// the best overall claim was rejected -> anomaly
			for _, c := range cands {
				if c.HasCoords {
					if c.Rejected != "" {
						info.RTTAnomaly = true
						info.Anomaly = fmt.Sprintf("%s says %s %s, but %s", c.Source, c.City, c.Country, c.Rejected)
					}
					break
				}
			}
			switch {
			case chosen >= 0:
				cands[chosen].Chosen = true
				c := cands[chosen]
				info.City, info.Region, info.Country = c.City, c.Region, c.Country
				info.Lat, info.Lon, info.Located = c.Lat, c.Lon, true
				info.Source, info.Confidence = c.Source, c.Confidence
				info.Priority = SourcePriority(c.Source)
				if c.Confidence >= 0.6 && rtt > 0 {
					anchors = append(anchors, Point{Lat: c.Lat, Lon: c.Lon, RTT: rtt, Name: c.City})
				}
			case info.RTTAnomaly && last != nil && last.Located:
				// every claim is impossible: interpolate from the previous located hop
				info.City, info.Country = last.City, last.Country
				info.Lat, info.Lon, info.Located = last.Lat, last.Lon, true
				info.Source, info.Confidence = SrcInterp, 0.25
				info.Priority = SourcePriority(SrcInterp)
			default:
				// no coordinates: keep the country from any source
				for ci := range cands {
					c := &cands[ci]
					if c.Country != "" {
						c.Chosen = true
						info.Country, info.City, info.Source, info.Confidence = c.Country, c.City, c.Source, c.Confidence*0.5
						info.Priority = SourcePriority(c.Source)
						break
					}
				}
			}
			for i := range cands {
				if cands[i].Priority == 0 {
					cands[i].Priority = SourcePriority(cands[i].Source)
				}
			}
			if info.Located {
				info.Discrepancies = computeDiscrepancies(info, cands)
			}
			info.Candidates = cands
			rs.Geo = info
			if info.Located {
				last = info
			}
		}
	}
	fixDetours(hops)
}

// fixDetours catches weak claims that would be a detour: a hop sitting between
// two reliably located hops in the same metro whose RTTs leave no time for a
// trip to the claimed place and back (Stockholm 33 ms → "Dublin" 31 ms →
// Stockholm 31.6 ms). The packet to the next hop passes through this one, so
// going there would add at least MinRTTms(distance).
func fixDetours(hops []trace.Hop) {
	type loc struct {
		hop  int
		info *Info
		rtt  float64
	}
	var all []loc
	for hi := range hops {
		for ri := range hops[hi].Responders {
			rs := &hops[hi].Responders[ri]
			if info, ok := rs.Geo.(*Info); ok && info != nil && info.Located {
				all = append(all, loc{hi, info, minF(rs.RTTs)})
			}
		}
	}
	strong := func(l loc) bool { return l.info.Confidence >= 0.6 && l.rtt > 0 }
	for i, x := range all {
		if x.info.Confidence >= 0.6 || x.info.Source == SrcInterp {
			continue
		}
		var prev, next *loc
		for j := i - 1; j >= 0 && prev == nil; j-- {
			if all[j].hop < x.hop && strong(all[j]) {
				prev = &all[j]
			}
		}
		for j := i + 1; j < len(all) && next == nil; j++ {
			if all[j].hop > x.hop && strong(all[j]) {
				next = &all[j]
			}
		}
		if prev == nil || next == nil {
			continue
		}
		p, n := prev.info, next.info
		if DistanceKm(p.Lat, p.Lon, n.Lat, n.Lon) > SlackKm {
			continue
		}
		d := DistanceKm(p.Lat, p.Lon, x.info.Lat, x.info.Lon)
		if d <= 2*SlackKm || next.rtt >= prev.rtt+MinRTTms(d) {
			continue
		}
		why := fmt.Sprintf("between hops in %s at %.1f and %.1f ms, a detour of %.0f km needs ≥ %.1f ms more",
			p.City, prev.rtt, next.rtt, d, MinRTTms(d))
		for ci := range x.info.Candidates {
			c := &x.info.Candidates[ci]
			if c.Source == x.info.Source && c.Rejected == "" && c.Lat == x.info.Lat && c.Lon == x.info.Lon {
				c.Rejected = why
			}
		}
		x.info.RTTAnomaly = true
		x.info.Anomaly = fmt.Sprintf("%s says %s %s, but %s", x.info.Source, x.info.City, x.info.Country, why)
		x.info.City, x.info.Region, x.info.Country = p.City, p.Region, p.Country
		x.info.Lat, x.info.Lon = p.Lat, p.Lon
		x.info.Source, x.info.Confidence = SrcInterp, 0.3
	}
}

func computeDiscrepancies(info *Info, cands []Candidate) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		if c.Chosen {
			continue
		}
		if c.City == "" && c.Country == "" {
			continue
		}
		diffCountry := info.Country != "" && c.Country != "" && !strings.EqualFold(info.Country, c.Country)
		dist := 0.0
		if info.Located && c.HasCoords {
			dist = DistanceKm(info.Lat, info.Lon, c.Lat, c.Lon)
		}
		if !diffCountry && dist < 150 {
			continue
		}
		loc := strings.Trim(strings.Join([]string{c.City, c.Country}, ", "), ", ")
		src := c.Source
		if c.Source == SrcGeoIP && c.Detail != "" {
			// strip extra notes after ';'
			d := strings.Split(c.Detail, ";")[0]
			src = fmt.Sprintf("%s(%s)", c.Source, strings.TrimSpace(d))
		}
		key := src + ":" + loc
		if seen[key] {
			continue
		}
		seen[key] = true
		var msg string
		if dist >= 150 {
			msg = fmt.Sprintf("%s says %s (%.0f km off)", src, loc, dist)
		} else {
			msg = fmt.Sprintf("%s says %s", src, loc)
		}
		if c.Rejected != "" {
			msg += " [rejected]"
		}
		out = append(out, msg)
	}
	return out
}

func minF(v []float64) float64 {
	m := 0.0
	for _, x := range v {
		if x > 0 && (m == 0 || x < m) {
			m = x
		}
	}
	return m
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
