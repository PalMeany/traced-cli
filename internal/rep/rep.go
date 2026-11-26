// Package rep checks how clean an IP address, an autonomous system or a
// domain is: local copies of Kinetio DTIH, Spamhaus DROP / ASN-DROP, FireHOL
// level1, Emerging Threats and the Tor exit list, plus the optional Spamhaus
// ZEN DNSBL and AbuseIPDB (with ABUSEIPDB_API_KEY). Each source reports on
// its own; Aggregate folds them into Clean / Low risk / Suspicious / Dirty.
package rep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/whois"
)

// Verdicts.
const (
	Clean      = "Clean"
	LowRisk    = "Low risk"
	Suspicious = "Suspicious"
	Dirty      = "Dirty"
)

// Statuses of a source.
const (
	StListed  = "listed"
	StClean   = "clean"
	StInfo    = "info" // listed, but not an abuse signal by itself (Tor, PBL)
	StSkipped = "skipped"
	StError   = "error"
)

// Source is the answer of one list / service.
type Source struct {
	Name    string         `json:"name"`
	Title   string         `json:"title"`
	Status  string         `json:"status"`
	Score   int            `json:"score"` // 0..100 contribution
	Summary string         `json:"summary,omitempty"`
	Matches int            `json:"matches,omitempty"`
	Types   map[string]int `json:"types,omitempty"` // attack type → count
	Details []string       `json:"details,omitempty"`
	Note    string         `json:"note,omitempty"` // stale cache etc.
}

// Report is the result for one query.
type Report struct {
	Query   string    `json:"query"`
	Kind    string    `json:"kind"` // ip | asn | domain
	IP      string    `json:"ip,omitempty"`
	ASN     int       `json:"asn,omitempty"`
	ASName  string    `json:"as_name,omitempty"`
	Prefix  string    `json:"prefix,omitempty"`
	Verdict string    `json:"verdict"`
	Score   int       `json:"score"`
	Sources []Source  `json:"sources"`
	Targets []*Report `json:"targets,omitempty"` // domain: per address, ip: its AS
	Notes   []string  `json:"notes,omitempty"`
	Checked time.Time `json:"checked"`
}

// Options of a check.
type Options struct {
	DNSBL        bool   // query zen.spamhaus.org for IPs
	DNSBLServer  string // resolver "ip[:port]" for the DNSBL (TRACED_DNSBL_RESOLVER)
	AbuseIPDBKey string // ABUSEIPDB_API_KEY
	WithASN      bool   // for an IP also check its AS
	NoNetwork    bool   // local feeds only (no DNSBL/AbuseIPDB/RIPEstat)
	// Prefixes of the AS when the caller already has them (saves a RIPEstat call).
	PrefixesV4, PrefixesV6 []string
}

// DefaultOptions reads the environment.
func DefaultOptions() Options {
	return Options{DNSBL: os.Getenv("TRACED_DNSBL") != "0", DNSBLServer: os.Getenv("TRACED_DNSBL_RESOLVER"),
		AbuseIPDBKey: strings.TrimSpace(os.Getenv("ABUSEIPDB_API_KEY")), WithASN: true}
}

// Verdict maps a score to a label.
func Verdict(score int) string {
	switch {
	case score <= 0:
		return Clean
	case score < 25:
		return LowRisk
	case score < 60:
		return Suspicious
	}
	return Dirty
}

// Aggregate folds the sources: the strongest signal sets the base, every
// further independent listing adds 5 (lists overlap — FireHOL level1 already
// contains DROP — so they are not summed). Informational hits count fully but
// never push past Low risk on their own.
func Aggregate(srcs []Source) (int, string) {
	var scores []int
	for _, s := range srcs {
		if (s.Status == StListed || s.Status == StInfo) && s.Score > 0 {
			scores = append(scores, s.Score)
		}
	}
	if len(scores) == 0 {
		return 0, Clean
	}
	sort.Sort(sort.Reverse(sort.IntSlice(scores)))
	total := scores[0]
	for _, s := range scores[1:] {
		if s >= 10 {
			total += 5
		}
	}
	if total > 100 {
		total = 100
	}
	return total, Verdict(total)
}

// ---------------- targets ----------------

// Check dispatches on the query type: "AS123", an IP or a domain.
func Check(ctx context.Context, q string, o Options) (*Report, error) {
	q = strings.TrimSpace(q)
	if n, ok := asn.ParseASN(q); ok {
		return CheckASN(ctx, n, o), nil
	}
	if a, err := netip.ParseAddr(q); err == nil {
		return CheckIP(ctx, a.Unmap(), o), nil
	}
	if !strings.Contains(q, ".") {
		return nil, fmt.Errorf("%q is not an IP, ASN or domain", q)
	}
	return CheckDomain(ctx, q, o)
}

// CheckDomain checks up to three addresses of the name; the worst wins.
func CheckDomain(ctx context.Context, name string, o Options) (*Report, error) {
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	addrs, err := net.DefaultResolver.LookupNetIP(c, "ip", name)
	cancel()
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: %v", name, err)
	}
	// v4 first, at most 2 v4 + 1 v6
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Unmap().Is4() && !addrs[j].Unmap().Is4() })
	var pick []netip.Addr
	n4, n6 := 0, 0
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() && n4 < 2 {
			pick = append(pick, a)
			n4++
		} else if a.Is6() && n6 < 1 {
			pick = append(pick, a)
			n6++
		}
	}
	r := &Report{Query: name, Kind: "domain", Checked: time.Now().UTC().Truncate(time.Second)}
	r.Targets = make([]*Report, len(pick))
	var wg sync.WaitGroup
	io := o
	io.WithASN = false // each AS is checked once below
	for i, a := range pick {
		wg.Add(1)
		go func(i int, a netip.Addr) {
			defer wg.Done()
			r.Targets[i] = CheckIP(ctx, a, io)
		}(i, a)
	}
	wg.Wait()
	for _, t := range r.Targets {
		if t.Score >= r.Score {
			r.Score, r.Verdict = t.Score, t.Verdict
		}
	}
	if o.WithASN && !o.NoNetwork {
		seen := map[int]bool{}
		var asns []int
		for _, t := range r.Targets {
			if t.ASN > 0 && !seen[t.ASN] {
				seen[t.ASN] = true
				asns = append(asns, t.ASN)
			}
		}
		out := make([]*Report, len(asns))
		for i, n := range asns {
			wg.Add(1)
			go func(i, n int) {
				defer wg.Done()
				so := o
				so.WithASN = false
				out[i] = CheckASN(ctx, n, so)
			}(i, n)
		}
		wg.Wait()
		r.Targets = append(r.Targets, out...)
	}
	if r.Verdict == "" {
		r.Verdict = Clean
	}
	return r, nil
}

func typeCount(es []feeds.Entry) map[string]int {
	m := map[string]int{}
	for _, e := range es {
		for _, t := range e.Types {
			m[t]++
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func fmtTypes(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var v []kv
	for k, n := range m {
		v = append(v, kv{k, n})
	}
	sort.Slice(v, func(i, j int) bool { return v[i].v > v[j].v || v[i].v == v[j].v && v[i].k < v[j].k })
	var s []string
	for _, x := range v {
		s = append(s, fmt.Sprintf("%s×%d", x.k, x.v))
	}
	return strings.Join(s, ", ")
}

var feedTitles = map[string]string{
	"kinetio": "Kinetio DTIH", "spamhaus-drop": "Spamhaus DROP", "spamhaus-asndrop": "Spamhaus ASN-DROP",
	"firehol-l1": "FireHOL level1", "et-block": "Emerging Threats", "tor-exit": "Tor exit", "zen": "Spamhaus ZEN (DNSBL)",
	"abuseipdb": "AbuseIPDB",
}

// kinetioScore rates Kinetio matches of one address.
func kinetioScore(es []feeds.Entry) int {
	s := 0
	for _, e := range es {
		v := 30 // subnet
		if e.Single() {
			v = 40
		}
		for _, t := range e.Types {
			if t == "exploit_attempt" || t == "bruteforce" || t == "proxy_abuse" {
				v += 10
				break
			}
		}
		if e.Confidence > 0 {
			c := e.Confidence
			if c > 1 { // published as a percentage
				c /= 100
			}
			v += int(15 * c)
		}
		s = max(s, v)
	}
	return min(s, 65)
}

// CheckIP checks one address.
func CheckIP(ctx context.Context, a netip.Addr, o Options) *Report {
	r := &Report{Query: a.String(), Kind: "ip", IP: a.String(), Checked: time.Now().UTC().Truncate(time.Second)}
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		r.Verdict = Clean
		r.Notes = append(r.Notes, "private / special-purpose address: not listed anywhere by definition")
		return r
	}
	var mu sync.Mutex
	add := func(s Source) {
		mu.Lock()
		r.Sources = append(r.Sources, s)
		mu.Unlock()
	}
	var wg sync.WaitGroup
	// local lists
	drop := "spamhaus-drop4"
	if a.Is6() {
		drop = "spamhaus-drop6"
	}
	for _, name := range []string{"kinetio", drop, "firehol-l1", "et-block", "tor-exit"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			key := name
			if strings.HasPrefix(name, "spamhaus-drop") {
				key = "spamhaus-drop"
			}
			s := Source{Name: key, Title: feedTitles[key]}
			set, note := feeds.NetSet(ctx, name)
			s.Note = note
			if set == nil {
				s.Status, s.Summary = StError, orStr(note, "feed unavailable")
				add(s)
				return
			}
			hits := set.Lookup(a)
			s.Matches = len(hits)
			if len(hits) == 0 {
				s.Status, s.Summary = StClean, "not listed"
				add(s)
				return
			}
			s.Status = StListed
			s.Types = typeCount(hits)
			for _, h := range hits {
				d := h.Prefix.String()
				if h.Ref != "" {
					d += " " + h.Ref
				}
				if len(h.Types) > 0 {
					d += " [" + strings.Join(h.Types, ",") + "]"
				}
				if h.Confidence > 0 {
					d += fmt.Sprintf(" conf %.2f", h.Confidence)
				}
				s.Details = append(s.Details, d)
			}
			switch key {
			case "kinetio":
				s.Score = kinetioScore(hits)
				rung := "address"
				if !hits[0].Single() {
					rung = "subnet " + hits[0].Prefix.String()
				}
				s.Summary = fmt.Sprintf("listed (%s): %s", rung, fmtTypes(s.Types))
			case "spamhaus-drop":
				s.Score = 90
				s.Summary = "in DROP " + hits[len(hits)-1].Prefix.String() + " " + hits[len(hits)-1].Ref + " — hijacked / criminal netblock"
			case "firehol-l1":
				s.Score = 50
				s.Summary = "in FireHOL level1 " + hits[0].Prefix.String()
			case "et-block":
				s.Score = 50
				s.Summary = "in ET block list " + hits[0].Prefix.String()
			case "tor-exit":
				s.Status, s.Score, s.Summary = StInfo, 15, "Tor exit node"
			}
			add(s)
		}(name)
	}
	// DNSBL
	if o.DNSBL && !o.NoNetwork {
		wg.Add(1)
		go func() {
			defer wg.Done()
			add(checkZen(ctx, a, o.DNSBLServer))
		}()
	} else {
		add(Source{Name: "zen", Title: feedTitles["zen"], Status: StSkipped, Summary: "disabled"})
	}
	// AbuseIPDB
	if o.AbuseIPDBKey == "" {
		add(Source{Name: "abuseipdb", Title: feedTitles["abuseipdb"], Status: StSkipped, Summary: "skipped: no API key (set ABUSEIPDB_API_KEY)"})
	} else if o.NoNetwork {
		add(Source{Name: "abuseipdb", Title: feedTitles["abuseipdb"], Status: StSkipped, Summary: "offline"})
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			add(checkAbuseIPDB(ctx, a, o.AbuseIPDBKey))
		}()
	}
	// the origin AS (ASN-DROP for the IP itself; the full AS check as a sub-report)
	var asr *Report
	if !o.NoNetwork {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ai, err := whois.LookupASN(ctx, net.IP(a.AsSlice()))
			if err != nil || ai == nil {
				mu.Lock()
				r.Notes = append(r.Notes, "origin AS unknown")
				mu.Unlock()
				return
			}
			mu.Lock()
			r.ASN, r.ASName, r.Prefix = ai.ASN, ai.Name, ai.Prefix
			mu.Unlock()
			dl, note := feeds.ASNDropList(ctx)
			s := Source{Name: "spamhaus-asndrop", Title: feedTitles["spamhaus-asndrop"], Note: note}
			switch {
			case dl == nil:
				s.Status, s.Summary = StError, orStr(note, "feed unavailable")
			case dl[ai.ASN].ASN != 0:
				d := dl[ai.ASN]
				s.Status, s.Score, s.Matches = StListed, 90, 1
				s.Summary = fmt.Sprintf("origin AS%d %s is in ASN-DROP", ai.ASN, d.Name)
			default:
				s.Status, s.Summary = StClean, fmt.Sprintf("origin AS%d not listed", ai.ASN)
			}
			add(s)
			if o.WithASN {
				so := o
				so.WithASN = false
				asr = CheckASN(ctx, ai.ASN, so)
			}
		}()
	}
	wg.Wait()
	sortSources(r.Sources)
	r.Score, r.Verdict = Aggregate(r.Sources)
	if asr != nil {
		asr.Query = "AS" + strconv.Itoa(asr.ASN)
		r.Targets = append(r.Targets, asr)
	}
	return r
}

var order = map[string]int{"spamhaus-drop": 0, "spamhaus-asndrop": 1, "zen": 2, "abuseipdb": 3, "kinetio": 4, "firehol-l1": 5, "et-block": 6, "tor-exit": 7}

func sortSources(s []Source) {
	sort.SliceStable(s, func(i, j int) bool { return order[s[i].Name] < order[s[j].Name] })
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---------------- AS ----------------

// ASNHits is what the lists say about an AS's address space.
type ASNHits struct {
	Inside   int            // listed networks inside announced prefixes
	Covering int            // listed networks covering announced prefixes
	Addr     int            // of which single addresses
	Types    map[string]int // attack types
	Sample   []string       // a few examples
}

// MatchPrefixes counts the entries of set that overlap the prefixes.
// Each listed network is counted once even when announced prefixes overlap.
func MatchPrefixes(set *feeds.Set, prefixes []string) ASNHits {
	h := ASNHits{Types: map[string]int{}}
	seen := map[netip.Prefix]bool{}
	for _, ps := range prefixes {
		p, err := netip.ParsePrefix(ps)
		if err != nil {
			continue
		}
		in, cov := set.Overlap(p)
		for _, e := range in {
			if seen[e.Prefix] {
				continue
			}
			seen[e.Prefix] = true
			h.Inside++
			if e.Single() {
				h.Addr++
			}
			for _, t := range e.Types {
				h.Types[t]++
			}
			if len(h.Sample) < 5 {
				s := e.Prefix.String()
				if e.Ref != "" {
					s += " " + e.Ref
				}
				h.Sample = append(h.Sample, s)
			}
		}
		for _, e := range cov {
			if seen[e.Prefix] {
				continue
			}
			seen[e.Prefix] = true
			h.Covering++
			if len(h.Sample) < 5 {
				h.Sample = append(h.Sample, e.Prefix.String()+" (covers "+p.String()+")")
			}
		}
	}
	if len(h.Types) == 0 {
		h.Types = nil
	}
	return h
}

// KinetioASNScore rates the number of Kinetio entries within an AS relative
// to its size: a big cloud with a few dozen scanners is not a dirty network,
// a small hoster where every tenth /24 scans is.
func KinetioASNScore(hits int, addressesV4 int64) int {
	if hits <= 0 {
		return 0
	}
	var s int
	switch {
	case hits < 5:
		s = 5
	case hits < 50:
		s = 15
	case hits < 500:
		s = 30
	default:
		s = 45
	}
	if addressesV4 > 0 {
		per24 := float64(hits) / (float64(addressesV4) / 256)
		switch {
		case per24 >= 0.5:
			s += 20
		case per24 >= 0.1:
			s += 10
		case per24 >= 0.02:
		case per24 >= 0.005:
			s -= 10
		default:
			s -= 15
		}
	}
	return max(1, min(s, 65))
}

// CheckASN checks an AS: ASN-DROP, then all listed networks within its
// announced prefixes (RIPEstat, cached).
func CheckASN(ctx context.Context, n int, o Options) *Report {
	r := &Report{Query: "AS" + strconv.Itoa(n), Kind: "asn", ASN: n, Checked: time.Now().UTC().Truncate(time.Second)}
	dl, note := feeds.ASNDropList(ctx)
	s := Source{Name: "spamhaus-asndrop", Title: feedTitles["spamhaus-asndrop"], Note: note}
	switch {
	case dl == nil:
		s.Status, s.Summary = StError, orStr(note, "feed unavailable")
	case dl[n].ASN != 0:
		s.Status, s.Score, s.Matches = StListed, 95, 1
		d := dl[n]
		r.ASName = d.Name
		s.Summary = fmt.Sprintf("AS%d %s (%s, %s) is run by cybercriminals per Spamhaus", n, d.Name, d.CC, d.Domain)
	default:
		s.Status, s.Summary = StClean, "not listed"
	}
	r.Sources = append(r.Sources, s)

	v4, v6 := o.PrefixesV4, o.PrefixesV6
	if v4 == nil && v6 == nil {
		var err error
		v4, v6, _, err = asn.Prefixes(ctx, n, o.NoNetwork)
		if err != nil {
			r.Notes = append(r.Notes, "announced prefixes unavailable ("+err.Error()+"): only ASN-DROP checked")
		}
	}
	addrs := asn.AddressCount(v4)
	if len(v4)+len(v6) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("checked %d IPv4 + %d IPv6 announced prefixes (%s IPv4 addresses)", len(v4), len(v6), human(addrs)))
		all := append(append([]string{}, v4...), v6...)
		names := []string{"kinetio", "spamhaus-drop", "firehol-l1", "et-block", "tor-exit"}
		out := make([]Source, len(names))
		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				out[i] = asnListSource(ctx, name, all, v4, v6, addrs)
			}(i, name)
		}
		wg.Wait()
		r.Sources = append(r.Sources, out...)
	}
	sortSources(r.Sources)
	r.Score, r.Verdict = Aggregate(r.Sources)
	return r
}

func asnListSource(ctx context.Context, name string, all, v4, v6 []string, addrs int64) Source {
	s := Source{Name: name, Title: feedTitles[name]}
	var sets []*feeds.Set
	if name == "spamhaus-drop" {
		for _, f := range []string{"spamhaus-drop4", "spamhaus-drop6"} {
			set, note := feeds.NetSet(ctx, f)
			if note != "" {
				s.Note = note
			}
			if set != nil {
				sets = append(sets, set)
			}
		}
	} else {
		set, note := feeds.NetSet(ctx, name)
		s.Note = note
		if set != nil {
			sets = append(sets, set)
		}
	}
	if len(sets) == 0 {
		s.Status, s.Summary = StError, orStr(s.Note, "feed unavailable")
		return s
	}
	var h ASNHits
	h.Types = map[string]int{}
	for _, set := range sets {
		x := MatchPrefixes(set, all)
		h.Inside += x.Inside
		h.Covering += x.Covering
		h.Addr += x.Addr
		for k, v := range x.Types {
			h.Types[k] += v
		}
		h.Sample = append(h.Sample, x.Sample...)
	}
	total := h.Inside + h.Covering
	s.Matches = total
	s.Details = h.Sample
	if len(h.Types) > 0 {
		s.Types = h.Types
	}
	if total == 0 {
		s.Status, s.Summary = StClean, "no listed networks in the announced space"
		return s
	}
	s.Status = StListed
	switch name {
	case "kinetio":
		s.Score = KinetioASNScore(total, addrs)
		s.Summary = fmt.Sprintf("%d entries (%d addresses, %d subnets): %s", total, h.Addr, total-h.Addr, fmtTypes(h.Types))
	case "spamhaus-drop":
		s.Score = 70
		s.Summary = fmt.Sprintf("%d DROP netblocks inside/over announced prefixes", total)
	case "firehol-l1":
		s.Score = min(45, 10+5*total)
		s.Summary = fmt.Sprintf("%d FireHOL level1 networks overlap", total)
	case "et-block":
		s.Score = min(35, 10+3*total)
		s.Summary = fmt.Sprintf("%d Emerging Threats entries", total)
	case "tor-exit":
		s.Status, s.Score = StInfo, 5
		s.Summary = fmt.Sprintf("%d Tor exit nodes hosted", total)
	}
	return s
}

func human(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return strconv.FormatInt(n, 10)
}

// ---------------- Spamhaus ZEN ----------------

// ZenResult is the interpretation of a zen.spamhaus.org answer.
type ZenResult struct {
	Listed  []string // SBL, CSS, XBL, PBL, DROP
	Blocked string   // non-empty: the query was refused (public resolver / rate limit)
	Policy  bool     // only PBL (policy, not abuse)
}

// ParseZen interprets the A records returned for a zen query. 127.255.255.x
// are error codes (252 typo, 254 query via public/open resolver, 255 excessive
// queries), never listings.
func ParseZen(addrs []string) ZenResult {
	var z ZenResult
	seen := map[string]bool{}
	pbl := true
	for _, s := range addrs {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !a.Is4() {
			continue
		}
		b := a.As4()
		if b[0] != 127 {
			continue
		}
		if b[1] == 255 && b[2] == 255 {
			switch b[3] {
			case 252:
				z.Blocked = "DNSBL rejected the query name (127.255.255.252)"
			case 254:
				z.Blocked = "DNSBL refuses queries via public/open resolvers (127.255.255.254); set TRACED_DNSBL_RESOLVER to your own resolver"
			case 255:
				z.Blocked = "DNSBL rate limit: excessive number of queries (127.255.255.255)"
			default:
				z.Blocked = "DNSBL error " + a.String()
			}
			continue
		}
		if b[1] != 0 || b[2] != 0 {
			continue
		}
		var l string
		switch b[3] {
		case 2:
			l = "SBL"
		case 3:
			l = "CSS"
		case 4, 5, 6, 7:
			l = "XBL"
		case 9:
			l = "DROP"
		case 10, 11:
			l = "PBL"
		default:
			continue
		}
		if l != "PBL" {
			pbl = false
		}
		if !seen[l] {
			seen[l] = true
			z.Listed = append(z.Listed, l)
		}
	}
	if z.Blocked != "" && len(z.Listed) == 0 {
		return z
	}
	z.Policy = len(z.Listed) > 0 && pbl
	sort.Strings(z.Listed)
	return z
}

// ZenName builds the DNSBL query name (reversed octets / nibbles).
func ZenName(a netip.Addr) string {
	a = a.Unmap()
	var b strings.Builder
	if a.Is4() {
		v := a.As4()
		fmt.Fprintf(&b, "%d.%d.%d.%d", v[3], v[2], v[1], v[0])
	} else {
		v := a.As16()
		for i := 15; i >= 0; i-- {
			if i != 15 {
				b.WriteByte('.')
			}
			fmt.Fprintf(&b, "%x.%x", v[i]&0xf, v[i]>>4)
		}
	}
	return b.String() + ".zen.spamhaus.org"
}

func resolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, server)
	}}
}

var (
	zenProbeMu sync.Mutex
	zenProbe   = map[string]string{} // resolver → "" ok | reason
)

// zenUsable sends the documented test point (127.0.0.2 is always listed): a
// resolver that cannot return it would turn every answer into a false "clean".
func zenUsable(ctx context.Context, res *net.Resolver, server string) string {
	zenProbeMu.Lock()
	if v, ok := zenProbe[server]; ok {
		zenProbeMu.Unlock()
		return v
	}
	zenProbeMu.Unlock()
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addrs, err := res.LookupHost(c, "2.0.0.127.zen.spamhaus.org")
	reason := ""
	z := ParseZen(addrs)
	switch {
	case z.Blocked != "":
		reason = z.Blocked
	case err != nil:
		reason = "resolver does not answer zen.spamhaus.org test point (" + shortDNSErr(err) + "); set TRACED_DNSBL_RESOLVER"
	case len(z.Listed) == 0:
		reason = "resolver returned no listing for the test point; DNSBL answers would be unreliable"
	}
	if c.Err() == nil { // do not cache a transient timeout of the whole command
		zenProbeMu.Lock()
		zenProbe[server] = reason
		zenProbeMu.Unlock()
	}
	return reason
}

func shortDNSErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsNotFound {
			return "NXDOMAIN"
		}
		if de.IsTimeout {
			return "timeout"
		}
		return de.Err
	}
	return err.Error()
}

func checkZen(ctx context.Context, a netip.Addr, server string) Source {
	s := Source{Name: "zen", Title: feedTitles["zen"]}
	res := resolver(server)
	if why := zenUsable(ctx, res, server); why != "" {
		s.Status, s.Summary = StSkipped, "skipped: "+why
		return s
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := res.LookupHost(c, ZenName(a))
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			s.Status, s.Summary = StClean, "not listed"
			return s
		}
		s.Status, s.Summary = StError, shortDNSErr(err)
		return s
	}
	z := ParseZen(addrs)
	switch {
	case z.Blocked != "" && len(z.Listed) == 0:
		s.Status, s.Summary = StSkipped, "skipped: "+z.Blocked
	case len(z.Listed) == 0:
		s.Status, s.Summary = StClean, "not listed"
	case z.Policy:
		s.Status, s.Score, s.Matches = StInfo, 5, 1
		s.Summary = "PBL only: end-user / dynamic range (policy, not abuse)"
		s.Details = addrs
	default:
		s.Status, s.Matches, s.Details = StListed, len(z.Listed), addrs
		s.Score = 60
		for _, l := range z.Listed {
			if l == "SBL" || l == "DROP" || l == "CSS" {
				s.Score = 80
			}
		}
		s.Summary = "listed in " + strings.Join(z.Listed, ", ")
	}
	return s
}
