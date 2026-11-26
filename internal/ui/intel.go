package ui

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/rep"
	"github.com/PalMeany/traced-cli/internal/store"
	"github.com/PalMeany/traced-cli/internal/trace"
)

// Human formats big counts: 1.2k, 3.4M, 5.6B.
func Human(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e4:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return strconv.FormatInt(n, 10)
}

// VerdictColor of a reputation verdict.
func VerdictColor(v string) string {
	switch v {
	case rep.Clean:
		return green
	case rep.LowRisk:
		return cyan
	case rep.Suspicious:
		return yellow
	case rep.Dirty:
		return red
	}
	return gray
}

func kvw(w io.Writer, k, v string) {
	if v != "" {
		fmt.Fprintf(w, "  %s %s\n", C(gray, Pad(k, 14)), v)
	}
}

// ASN prints a provider profile.
func ASN(w io.Writer, r *asn.Report, listPrefixes bool) {
	if r == nil {
		return
	}
	head := fmt.Sprintf("AS%d", r.ASN)
	fmt.Fprintf(w, "\n%s %s %s\n", C(bold, "ASN"), C(cyan, head), r.Name)
	if r.IP != "" {
		kvw(w, "query", r.Query+" → "+r.IP+" "+C(gray, r.Prefix))
	}
	if k := r.Rank; k != nil {
		cl := ""
		if k.Clique {
			cl = C(magenta, " · tier-1 clique")
		}
		kvw(w, "CAIDA rank", fmt.Sprintf("#%d%s", k.Rank, cl))
		kvw(w, "organization", strings.TrimSpace(k.Org+" "+C(gray, k.CountryName)))
		kvw(w, "customer cone", fmt.Sprintf("%s AS · %s prefixes · %s addresses", Human(int64(k.ConeASNs)), Human(int64(k.ConePrefixes)), Human(k.ConeAddresses)))
		kvw(w, "neighbours", fmt.Sprintf("%d upstream · %d peers · %d customers%s", k.Providers, k.Peers, k.Customers,
			map[bool]string{true: fmt.Sprintf(" · %d siblings", k.Siblings), false: ""}[k.Siblings > 0]))
	}
	if p := r.PeeringDB; p != nil {
		fmt.Fprintf(w, "\n%s %s\n", C(bold, "PeeringDB"), C(gray, fmt.Sprintf("net %d, updated %s", p.ID, shortDate(p.Updated))))
		kvw(w, "type", p.Type)
		kvw(w, "traffic", orDash(p.Traffic))
		kvw(w, "ratio", p.Ratio)
		kvw(w, "scope", p.Scope)
		pol := p.Policy
		if p.PolicyLocations != "" {
			pol += C(gray, " · locations "+p.PolicyLocations)
		}
		if p.PolicyContracts != "" {
			pol += C(gray, " · contracts "+p.PolicyContracts)
		}
		kvw(w, "peering policy", pol)
		kvw(w, "policy url", p.PolicyURL)
		kvw(w, "website", p.Website)
		kvw(w, "IRR as-set", p.IRRASSet)
		if p.Prefixes4+p.Prefixes6 > 0 {
			kvw(w, "max prefixes", fmt.Sprintf("v4 %d · v6 %d (declared)", p.Prefixes4, p.Prefixes6))
		}
		kvw(w, "exchanges", fmt.Sprintf("%d IX, %d facilities", p.IXCount, p.FacCount))
		for i, x := range p.IXs {
			if i == 12 {
				fmt.Fprintf(w, "  %s … %d more\n", Pad("", 14), len(p.IXs)-12)
				break
			}
			loc := strings.TrimSpace(x.City + " " + x.Country)
			rs := ""
			if x.RSPeer {
				rs = C(gray, " RS")
			}
			fmt.Fprintf(w, "  %s %s %s %s%s\n", Pad("", 14), Pad(Trunc(x.Name, 38), 38), C(gray, Pad(Trunc(loc, 22), 22)), speed(x.SpeedMb), rs)
		}
		if len(p.Facilities) > 0 {
			var names []string
			for i, f := range p.Facilities {
				if i == 8 {
					names = append(names, fmt.Sprintf("… +%d", len(p.Facilities)-8))
					break
				}
				names = append(names, f.Name+C(gray, " ("+f.City+")"))
			}
			kvw(w, "facilities", strings.Join(names, ", "))
		}
	}
	if rt := r.Routing; rt != nil {
		fmt.Fprintf(w, "\n%s %s\n", C(bold, "BGP (RIPEstat)"), C(gray, rt.Holder))
		pf := fmt.Sprintf("%d IPv4 · %d IPv6", rt.CountV4, rt.CountV6)
		if rt.AddressesV4 > 0 {
			pf += C(gray, fmt.Sprintf(" · %s IPv4 addresses", Human(rt.AddressesV4)))
		}
		if rt.Slash48sV6 > 0 {
			pf += C(gray, fmt.Sprintf(" · %s IPv6 /48s", Human(rt.Slash48sV6)))
		}
		kvw(w, "announced", pf)
		if rt.VisV4Total > 0 {
			kvw(w, "visibility", fmt.Sprintf("v4 %d/%d · v6 %d/%d RIS peers", rt.VisV4Seeing, rt.VisV4Total, rt.VisV6Seeing, rt.VisV6Total))
		}
		if rt.Left+rt.Right > 0 {
			kvw(w, "neighbours", fmt.Sprintf("%d upstream-side · %d downstream-side · %d uncertain", rt.Left, rt.Right, rt.Uncertain))
		}
		if len(rt.Upstreams) > 0 {
			var u []string
			for _, n := range rt.Upstreams {
				if n.Name != "" {
					u = append(u, fmt.Sprintf("AS%d (%s)", n.ASN, Trunc(n.Name, 18)))
				} else {
					u = append(u, fmt.Sprintf("AS%d", n.ASN))
				}
			}
			kvw(w, "top upstreams", strings.Join(u, ", "))
		}
		kvw(w, "first seen", shortDate(rt.FirstSeen))
		if h := rt.History; h != nil && len(h.Points) > 0 {
			var pts []string
			for _, pt := range h.Points {
				pts = append(pts, fmt.Sprintf("%s:%d", pt.Time[:min(7, len(pt.Time))], pt.Prefixes))
			}
			kvw(w, "bgp history", fmt.Sprintf("%s → %s (peak %d pfx)  %s", h.FirstSeen, h.LastSeen, h.Peak, C(gray, strings.Join(pts, " "))))
		}
		if listPrefixes {
			printPrefixes(w, "IPv4", rt.V4)
			printPrefixes(w, "IPv6", rt.V6)
		} else if len(rt.V4)+len(rt.V6) > 0 {
			ex := append(append([]string{}, first(rt.V4, 4)...), first(rt.V6, 2)...)
			kvw(w, "prefixes", strings.Join(ex, ", ")+C(gray, " … (--prefixes for all)"))
		}
	}
	if e := r.Eyeballs; e != nil {
		fmt.Fprintf(w, "\n%s %s\n", C(bold, "Eyeballs (APNIC Labs)"), C(gray, e.Date))
		kvw(w, "users", fmt.Sprintf("%s ≈ %.3f%% of the Internet", Human(e.Users), e.PctWorld))
		for i, x := range e.Top {
			if i == 5 {
				break
			}
			kvw(w, x.CC, fmt.Sprintf("%s users · %.2f%% of country · rank %d", Human(x.Users), x.PctCountry, x.Rank))
		}
	}
	srcLine(w, r.Sources)
	for _, n := range r.Notes {
		Note(w, n)
	}
}

func first(v []string, n int) []string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func printPrefixes(w io.Writer, fam string, v []string) {
	if len(v) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s %d\n", C(gray, Pad(fam, 14)), len(v))
	line := "  " + Pad("", 15)
	for i, p := range v {
		if len(line)+len(p) > 110 {
			fmt.Fprintln(w, line)
			line = "  " + Pad("", 15)
		}
		line += p + " "
		if i == 999 {
			line += C(gray, fmt.Sprintf("… %d more", len(v)-1000))
			break
		}
	}
	fmt.Fprintln(w, line)
}

func speed(mb int) string {
	switch {
	case mb >= 1000000:
		return fmt.Sprintf("%gT", float64(mb)/1e6)
	case mb >= 1000:
		return fmt.Sprintf("%gG", float64(mb)/1e3)
	case mb > 0:
		return fmt.Sprintf("%dM", mb)
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return C(gray, "not declared")
	}
	return s
}

func srcLine(w io.Writer, ss []asn.Source) {
	var parts []string
	for _, s := range ss {
		switch {
		case s.Error != "" && s.OK:
			parts = append(parts, C(yellow, s.Name+" partial: "+s.Error))
		case s.Error != "":
			parts = append(parts, C(red, s.Name+": "+s.Error))
		case s.Skipped != "":
			parts = append(parts, C(gray, s.Name+": "+s.Skipped))
		default:
			t := s.Name + " ✓"
			if s.Cached {
				t += " cached"
			}
			parts = append(parts, C(gray, t))
		}
	}
	fmt.Fprintf(w, "\n%s %s\n", C(gray, "sources:"), strings.Join(parts, C(gray, " · ")))
}

// Rep prints a reputation report.
func Rep(w io.Writer, r *rep.Report) {
	if r == nil {
		return
	}
	repOne(w, r, 0)
}

func repOne(w io.Writer, r *rep.Report, depth int) {
	title := r.Query
	switch r.Kind {
	case "ip":
		if r.ASN > 0 {
			title += C(gray, fmt.Sprintf("  AS%d %s %s", r.ASN, Trunc(r.ASName, 40), r.Prefix))
		}
	case "asn":
		if r.ASName != "" {
			title += " " + r.ASName
		}
	}
	label := "Reputation"
	if depth > 0 {
		label = "  └ " + strings.ToUpper(r.Kind)
	}
	fmt.Fprintf(w, "\n%s %s  %s\n", C(bold, label), title, C(bold+VerdictColor(r.Verdict), fmt.Sprintf("%s (%d/100)", r.Verdict, r.Score)))
	ind := strings.Repeat("  ", depth)
	for _, s := range r.Sources {
		var mark, col string
		switch s.Status {
		case rep.StListed:
			mark, col = "✗", red
			if s.Score < 25 {
				col = yellow
			}
		case rep.StInfo:
			mark, col = "•", cyan
		case rep.StClean:
			mark, col = "✓", green
		case rep.StSkipped:
			mark, col = "–", gray
		default:
			mark, col = "!", yellow
		}
		sum := s.Summary
		if s.Score > 0 {
			sum += C(gray, fmt.Sprintf(" [+%d]", s.Score))
		}
		fmt.Fprintf(w, "%s  %s %s %s\n", ind, C(col, mark), Pad(s.Title, 22), sum)
		if s.Status == rep.StListed && len(s.Details) > 0 && depth == 0 {
			fmt.Fprintf(w, "%s    %s %s\n", ind, Pad("", 22), C(gray, strings.Join(first(s.Details, 5), "; ")))
		}
		if s.Note != "" {
			fmt.Fprintf(w, "%s    %s %s\n", ind, Pad("", 22), C(yellow, s.Note))
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "%s  %s\n", ind, C(gray, "› "+n))
	}
	for _, t := range r.Targets {
		repOne(w, t, depth+1)
	}
}

// Feeds prints the feed table.
func Feeds(w io.Writer, st []feeds.Status) {
	fmt.Fprintf(w, "%s %s\n", C(bold, "feeds"), C(gray, feeds.Dir()))
	for _, s := range st {
		age := C(red, "missing")
		if s.Present {
			age = ago(s.Fetched)
			if s.Fresh {
				age = C(green, age)
			} else {
				age = C(yellow, age+" stale")
			}
		}
		fmt.Fprintf(w, "  %s %s %s %s %s\n", Pad(s.Name, 17), Pad(age, 16), Pad(fmt.Sprintf("%d", s.Entries), 7),
			C(gray, Pad(Human(s.Size)+"B", 7)), s.Title)
		if s.Error != "" {
			fmt.Fprintf(w, "  %s %s\n", Pad("", 17), C(yellow, "last error: "+s.Error))
		}
	}
	fmt.Fprintln(w, C(gray, "  refresh: traced feeds update [name…] [--force]; stale feeds refresh on use (TRACED_FEEDS_AUTO=0 disables)"))
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// FeedResults prints the outcome of `traced feeds update`.
func FeedResults(w io.Writer, rs []feeds.Result) {
	for _, r := range rs {
		switch {
		case r.Err != nil:
			fmt.Fprintf(w, "  %s %s %s\n", C(red, "✗"), Pad(r.Name, 17), C(yellow, r.Error)+C(gray, " (old copy kept)"))
		case r.Updated:
			fmt.Fprintf(w, "  %s %s %d entries %s\n", C(green, "✓"), Pad(r.Name, 17), r.Entries, C(gray, r.Took.Round(100*time.Millisecond).String()))
		default:
			fmt.Fprintf(w, "  %s %s %d entries %s\n", C(gray, "="), Pad(r.Name, 17), r.Entries, C(gray, "up to date"))
		}
	}
}

// PathIntel prints the AS profiles and cable hints attached to a trace.
func PathIntel(w io.Writer, r *trace.Result) {
	ex := app.ExtraOf(r)
	if ex == nil {
		return
	}
	if len(ex.ASNs) > 0 {
		fmt.Fprintln(w, C(bold, "\nAS on the path"))
		seen := map[int]bool{}
		var order []int
		for _, a := range store.ASPath(r) {
			if !seen[a] {
				seen[a] = true
				order = append(order, a)
			}
		}
		for k := range ex.ASNs {
			n, _ := strconv.Atoi(k)
			if !seen[n] {
				seen[n] = true
				order = append(order, n)
			}
		}
		for _, n := range order {
			b := ex.ASNs[strconv.Itoa(n)]
			if b == nil {
				continue
			}
			var parts []string
			if b.Rank > 0 {
				parts = append(parts, fmt.Sprintf("rank #%d", b.Rank))
			}
			if b.ConeASNs > 0 {
				parts = append(parts, fmt.Sprintf("cone %s AS", Human(int64(b.ConeASNs))))
			}
			if b.Type != "" {
				parts = append(parts, b.Type)
			}
			if b.Traffic != "" {
				parts = append(parts, b.Traffic)
			}
			if b.PrefixesV4+b.PrefixesV6 > 0 {
				parts = append(parts, fmt.Sprintf("%d/%d pfx", b.PrefixesV4, b.PrefixesV6))
			}
			if b.Users > 0 {
				parts = append(parts, fmt.Sprintf("%s users %s", Human(b.Users), b.UsersCC))
			}
			if b.IXCount > 0 {
				parts = append(parts, fmt.Sprintf("%d IX", b.IXCount))
			}
			v := ""
			if b.Rep != "" {
				v = C(VerdictColor(b.Rep), b.Rep)
			}
			fmt.Fprintf(w, "  %s %s %s %s\n", C(cyan, Pad(fmt.Sprintf("AS%d", n), 9)), Pad(Trunc(b.Name, 30), 30), Pad(v, 11), C(gray, strings.Join(parts, " · ")))
		}
	}
	if len(ex.IXPs) > 0 {
		fmt.Fprintln(w, C(bold, "\nInternet Exchanges (IX) on path"))
		for _, x := range ex.IXPs {
			loc := strings.Trim(strings.Join([]string{x.City, x.Country}, ", "), ", ")
			via := x.Prefix
			if via == "" && x.Via != "" {
				via = x.Via
			}
			fmt.Fprintf(w, "  hop %-2d %s %s %s %s\n", x.TTL, C(magenta, Pad(x.Name, 24)), Pad(loc, 18), C(gray, x.IP), C(gray, via))
		}
	}
	if len(ex.PrefixBGP) > 0 {
		fmt.Fprintln(w, C(bold, "\nBGP prefix upstreams & history")+C(gray, " (where hop prefixes are announced)"))
		var pfxs []string
		for k := range ex.PrefixBGP {
			pfxs = append(pfxs, k)
		}
		sort.Strings(pfxs)
		for _, k := range pfxs {
			pb := ex.PrefixBGP[k]
			if pb == nil {
				continue
			}
			var ups []string
			for i, u := range pb.Upstreams {
				if i == 4 {
					break
				}
				lbl := fmt.Sprintf("AS%d", u.ASN)
				if u.Name != "" {
					lbl += " " + Trunc(u.Name, 16)
				}
				if u.Pct > 0 {
					lbl += fmt.Sprintf(" (%.0f%%)", u.Pct)
				}
				ups = append(ups, lbl)
			}
			upStr := C(gray, "direct / none")
			if len(ups) > 0 {
				upStr = strings.Join(ups, ", ")
			}
			histNote := ""
			if pb.Changes > 0 {
				histNote = C(yellow, fmt.Sprintf(" · %d origin change(s)", pb.Changes))
			} else if len(pb.History) > 0 {
				histNote = C(gray, fmt.Sprintf(" · since %s", pb.History[0].Start))
			}
			fmt.Fprintf(w, "  %s %s → %s%s\n", C(cyan, Pad(pb.Prefix, 19)), C(gray, fmt.Sprintf("AS%-7d", pb.OriginASN)), upStr, histNote)
		}
	}
	if ex.NAT != nil {
		NAT(w, ex.NAT)
	}
	if ex.MTU != nil {
		MTU(w, ex.MTU)
	}
	// Geolocation source discrepancies across hops
	var discLines []string
	for _, h := range r.Hops {
		for _, rs := range h.Responders {
			if g := app.InfoOf(&rs); g != nil && len(g.Discrepancies) > 0 {
				discLines = append(discLines, fmt.Sprintf("  hop %-2d %s (%s: %s) vs %s", h.TTL, rs.IP, g.Source, g.Label(), strings.Join(first(g.Discrepancies, 2), "; ")))
			}
		}
	}
	if len(discLines) > 0 {
		fmt.Fprintln(w, C(bold, "\nGeo source discrepancies")+C(gray, " (highest-priority source chosen)"))
		for _, l := range first(discLines, 6) {
			fmt.Fprintln(w, C(gray, l))
		}
	}
	if len(ex.Cables) > 0 {
		fmt.Fprintln(w, C(bold, "\nSubmarine cables")+C(gray, " (heuristic: cables landing near both ends of a long segment)"))
		for _, s := range ex.Cables {
			var names []string
			for _, c := range s.Cables {
				names = append(names, c.Name)
			}
			fmt.Fprintf(w, "  hop %d→%d %s → %s %s: %s\n", s.FromTTL, s.ToTTL, s.From, s.To, C(gray, fmt.Sprintf("%.0f km", s.Km)), strings.Join(names, ", "))
		}
	}
	if len(ex.Backbones) > 0 {
		fmt.Fprintln(w, C(bold, "\nTerrestrial backbones")+C(gray, " (the path enters ASes whose backbone map is known; traced map shows them)"))
		for _, b := range ex.Backbones {
			var hops []string
			for _, t := range b.TTLs {
				hops = append(hops, strconv.Itoa(t))
			}
			fmt.Fprintf(w, "  %s %s %s\n", C(cyan, Pad(fmt.Sprintf("AS%d", b.ASN), 9)), Pad(Trunc(b.Provider, 30), 30), C(gray, "hops "+strings.Join(hops, ",")))
			for _, l := range b.Links {
				fmt.Fprintf(w, "    hop %d→%d ≈ %s — %s %s\n", l.FromTTL, l.ToTTL, orDash(l.From), orDash(l.To), C(gray, fmt.Sprintf("(ends %.0f km off)", l.Distance)))
			}
		}
	}
}

// RepBrief is one line for whois.
func RepBrief(r *rep.Report) string {
	if r == nil {
		return ""
	}
	var listed []string
	for _, s := range r.Sources {
		if s.Status == rep.StListed || s.Status == rep.StInfo {
			listed = append(listed, s.Title)
		}
	}
	sort.Strings(listed)
	out := C(VerdictColor(r.Verdict), fmt.Sprintf("%s (%d/100)", r.Verdict, r.Score))
	if len(listed) > 0 {
		out += C(gray, " · "+strings.Join(listed, ", "))
	}
	return out
}

// ASNShort is the compact profile shown under whois.
func ASNShort(w io.Writer, r *asn.Report) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "\n%s %s %s\n", C(bold, "ASN"), C(cyan, fmt.Sprintf("AS%d", r.ASN)), r.Name)
	if k := r.Rank; k != nil {
		kv := fmt.Sprintf("#%d · cone %s AS / %s prefixes / %s addresses · %d up · %d peers · %d customers", k.Rank,
			Human(int64(k.ConeASNs)), Human(int64(k.ConePrefixes)), Human(k.ConeAddresses), k.Providers, k.Peers, k.Customers)
		kvw(w, "CAIDA rank", kv)
	}
	if p := r.PeeringDB; p != nil {
		kvw(w, "PeeringDB", strings.Trim(strings.Join([]string{p.Type, p.Traffic, p.Ratio, "policy " + p.Policy,
			fmt.Sprintf("%d IX / %d fac", p.IXCount, p.FacCount)}, " · "), " ·"))
	}
	if rt := r.Routing; rt != nil {
		kvw(w, "announced", fmt.Sprintf("%d IPv4 · %d IPv6 prefixes · %s IPv4 addresses", rt.CountV4, rt.CountV6, Human(rt.AddressesV4)))
	}
	if e := r.Eyeballs; e != nil && len(e.Top) > 0 {
		kvw(w, "eyeballs", fmt.Sprintf("%s users (%.2f%% of %s, %.3f%% of the Internet)", Human(e.Users), e.Top[0].PctCountry, e.Top[0].CC, e.PctWorld))
	}
	for _, s := range r.Sources {
		if s.Error != "" {
			kvw(w, s.Name, C(yellow, s.Error))
		}
	}
}

// RepLines prints one verdict line per address (whois), with the listings.
func RepLines(w io.Writer, rs []*rep.Report) {
	if len(rs) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s %s\n", C(bold, "Reputation"), C(gray, "(traced rep <ip> for details)"))
	for _, r := range rs {
		fmt.Fprintf(w, "  %s %s\n", Pad(r.Query, 26), RepBrief(r))
		for _, s := range r.Sources {
			if s.Status == rep.StListed || s.Status == rep.StInfo {
				fmt.Fprintf(w, "  %s %s %s\n", Pad("", 26), C(gray, Pad(s.Title, 20)), s.Summary)
			}
		}
	}
}

// PrefixBGP prints BGP upstreams and routing history for one prefix.
func PrefixBGP(w io.Writer, pb *asn.PrefixBGP) {
	if pb == nil {
		return
	}
	orig := fmt.Sprintf("AS%d", pb.OriginASN)
	if pb.OriginName != "" {
		orig += " " + pb.OriginName
	}
	fmt.Fprintf(w, "\n%s %s  %s %s\n", C(bold, "BGP Prefix"), C(cyan, pb.Prefix), orig, C(gray, fmt.Sprintf("(%d RIS peers, %s)", pb.RISPeers, pb.Source)))
	if len(pb.Upstreams) > 0 {
		fmt.Fprintf(w, "  %s\n", C(gray, "upstreams (via):"))
		for _, u := range pb.Upstreams {
			name := u.Name
			if name == "" {
				name = "—"
			}
			pct := ""
			if u.Pct > 0 {
				pct = fmt.Sprintf("  %.1f%% (%d peers)", u.Pct, u.Peers)
			}
			fmt.Fprintf(w, "    %s %s%s\n", C(cyan, Pad(fmt.Sprintf("AS%d", u.ASN), 9)), Pad(Trunc(name, 30), 30), C(gray, pct))
		}
	}
	if len(pb.History) > 0 {
		fmt.Fprintf(w, "  %s", C(gray, "history:"))
		if pb.Changes > 0 {
			fmt.Fprintf(w, " %s", C(yellow, fmt.Sprintf("%d origin change(s)", pb.Changes)))
		}
		fmt.Fprintln(w)
		for _, ev := range pb.History {
			st := C(gray, ev.Start+" .. "+ev.End)
			if ev.Active {
				st = C(green, ev.Start+" .. now")
			}
			name := ""
			if ev.Name != "" {
				name = " " + ev.Name
			}
			fmt.Fprintf(w, "    %s%s  %s\n", C(cyan, fmt.Sprintf("AS%d", ev.ASN)), name, st)
		}
	}
}

// MTU prints ICMP DF + TCP MSS/PMTUD path MTU probe results.
func MTU(w io.Writer, m *trace.MTUResult) {
	if m == nil {
		return
	}
	mtuStr := C(yellow, "unknown")
	if m.PathMTU > 0 {
		col := green
		if m.PathMTU < 1500 {
			col = yellow
		}
		if m.PathMTU < 1300 {
			col = red
		}
		mtuStr = C(bold+col, fmt.Sprintf("%d bytes", m.PathMTU))
	}
	fmt.Fprintf(w, "\n%s %s → %s (%s)\n", C(bold, "Path MTU"), mtuStr, m.TargetIP, C(gray, fmt.Sprintf("%.0f ms", m.Duration)))
	printMTUProto := func(p *trace.MTUProbeResult) {
		if p == nil {
			return
		}
		label := strings.ToUpper(p.Proto)
		if p.Error != "" && p.PathMTU == 0 {
			kvw(w, label, C(red, p.Error))
			return
		}
		parts := []string{fmt.Sprintf("MTU %d", p.PathMTU)}
		if p.MSS > 0 {
			parts = append(parts, fmt.Sprintf("MSS %d (MTU %d)", p.MSS, p.MSSMTU))
		}
		if p.ReportedMTU > 0 {
			parts = append(parts, fmt.Sprintf("reported %d", p.ReportedMTU))
		}
		if p.DropHopTTL > 0 || p.DropHopIP != "" {
			dh := p.DropHopIP
			if p.DropHopTTL > 0 {
				dh = fmt.Sprintf("hop %d %s", p.DropHopTTL, dh)
			}
			parts = append(parts, C(yellow, "drops at "+strings.TrimSpace(dh)))
		}
		if p.Note != "" {
			parts = append(parts, C(gray, p.Note))
		}
		kvw(w, label, strings.Join(parts, " · "))
		if len(p.Steps) > 0 {
			var seq []string
			for _, st := range p.Steps {
				mark := C(green, "✓")
				if !st.Passed {
					mark = C(red, "✗")
				}
				seq = append(seq, fmt.Sprintf("%d%s", st.Size, mark))
			}
			kvw(w, label+" steps", strings.Join(seq, " "))
		}
	}
	printMTUProto(m.ICMP)
	printMTUProto(m.TCP)
}

// NAT prints NAT / double-triple NAT / CGNAT detection.
func NAT(w io.Writer, n *trace.NATResult) {
	if n == nil {
		return
	}
	col := green
	label := "no NAT (direct)"
	switch {
	case n.Layers == 1 && n.CGNAT:
		col, label = yellow, "CGNAT (100.64.0.0/10)"
	case n.Layers == 1:
		col, label = cyan, "single NAT (1 layer)"
	case n.Layers == 2:
		col, label = yellow, "double NAT (2 layers)"
	case n.Layers == 3:
		col, label = red, "triple NAT (3 layers)"
	case n.Layers > 3:
		col, label = red, fmt.Sprintf("multi-NAT (%d layers)", n.Layers)
	}
	if n.CGNAT && n.Layers > 1 {
		label += " + CGNAT"
	}
	fmt.Fprintf(w, "\n%s %s\n", C(bold, "NAT"), C(bold+col, label))
	if n.LocalIP != "" || n.PublicIP != "" {
		kvw(w, "addresses", fmt.Sprintf("local %s → public %s", orDash(n.LocalIP), orDash(n.PublicIP)))
	}
	if len(n.Evidence) > 0 {
		kvw(w, "evidence", C(gray, strings.Join(first(n.Evidence, 5), "; ")))
	}
}
