// Package ui renders traces, WHOIS reports, SNI probes and diffs for the terminal.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/store"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/whois"
	"golang.org/x/term"
)

// Color toggles ANSI output.
var Color = os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
	gray    = "\x1b[90m"
)

// C wraps s in a color code when colors are enabled.
func C(code, s string) string {
	if !Color || s == "" {
		return s
	}
	return code + s + reset
}

// Width counts visible runes (ANSI escapes excluded).
func Width(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			if r == 'm' {
				esc = false
			}
		case r == 0x1b:
			esc = true
		default:
			n++
		}
	}
	return n
}

// Pad right-pads s to w visible columns, truncating with an ellipsis.
func Pad(s string, w int) string {
	if Width(s) > w {
		return Trunc(s, w)
	}
	return s + strings.Repeat(" ", w-Width(s))
}

// Trunc shortens a plain string to w runes.
func Trunc(s string, w int) string {
	if utf8.RuneCountInString(s) <= w {
		return s
	}
	if w <= 1 {
		return "…"
	}
	r := []rune(stripANSI(s))
	if len(r) <= w {
		return string(r)
	}
	return string(r[:w-1]) + "…"
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		if r == 0x1b {
			esc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// RTTColor colors a latency value.
func RTTColor(ms float64) string {
	switch {
	case ms <= 0:
		return gray
	case ms < 30:
		return green
	case ms < 120:
		return yellow
	default:
		return red
	}
}

// FmtRTT formats one RTT.
func FmtRTT(ms float64) string {
	switch {
	case ms <= 0:
		return "*"
	case ms < 10:
		return fmt.Sprintf("%.2f", ms)
	case ms < 100:
		return fmt.Sprintf("%.1f", ms)
	}
	return fmt.Sprintf("%.0f", ms)
}

// SourceBadge renders the geo source.
func SourceBadge(src string) string {
	col := map[string]string{geo.SrcRDNS: cyan, geo.SrcIXP: magenta, geo.SrcGeofeed: green, geo.SrcIPMap: blue,
		geo.SrcGeoIP: yellow, geo.SrcMMDB: yellow, geo.SrcRIR: yellow, geo.SrcInterp: gray}[src]
	if src == "" {
		return ""
	}
	return C(col, src)
}

func asLabel(a *whois.ASInfo) string {
	if a == nil {
		return ""
	}
	name := a.Name
	if i := strings.Index(name, " - "); i > 0 {
		name = name[:i]
	}
	if i := strings.Index(name, ","); i > 0 {
		name = name[:i]
	}
	return fmt.Sprintf("AS%d %s", a.ASN, name)
}

// HopHeader prints the column header.
func HopHeader(w io.Writer) {
	fmt.Fprintln(w, C(dim, fmt.Sprintf("%3s  %-44s %-24s %-22s %-8s %s", "#", "host", "network", "location", "source", "rtt ms")))
}

// Hop renders one hop (with ECMP branches on extra lines).
func Hop(w io.Writer, h *trace.Hop, showHost bool) {
	if len(h.Responders) == 0 {
		fmt.Fprintf(w, "%3d  %s\n", h.TTL, C(gray, strings.Repeat("* ", h.Sent)))
		return
	}
	for i := range h.Responders {
		rs := &h.Responders[i]
		ttl := fmt.Sprintf("%3d", h.TTL)
		if i > 0 {
			ttl = C(gray, "  ├")
			if i == len(h.Responders)-1 {
				ttl = C(gray, "  └")
			}
		}
		name := rs.IP
		if showHost && rs.Host != "" {
			name = rs.Host + C(gray, " ("+rs.IP+")")
		}
		if rs.Final {
			name = C(bold, name)
		}
		info := app.InfoOf(rs)
		loc, src := "", ""
		var flags []string
		if info != nil {
			loc = info.Label()
			if info.IXP != nil {
				loc = info.IXP.Name
			}
			src = SourceBadge(info.Source)
			if info.RTTAnomaly {
				flags = append(flags, C(red, "⚠ rtt"))
			}
		}
		if len(rs.MPLS) > 0 {
			var ls []string
			for _, l := range rs.MPLS {
				ls = append(ls, fmt.Sprint(l.Label))
			}
			flags = append(flags, C(magenta, "MPLS "+strings.Join(ls, "/")))
		}
		if i == 0 && len(h.Responders) > 1 {
			flags = append(flags, C(cyan, fmt.Sprintf("ECMP×%d", len(h.Responders))))
		}
		if rs.Kind == trace.KindUnreachable && !rs.Final {
			flags = append(flags, C(red, "!unreach"))
		}
		var rtts []string
		// per-flow RTTs in probe order; lost probes of the hop shown on the primary line
		for _, p := range h.Probes {
			if p.Lost {
				if i == 0 {
					rtts = append(rtts, C(gray, "*"))
				}
				continue
			}
			if p.IP == rs.IP {
				rtts = append(rtts, C(RTTColor(p.RTT), FmtRTT(p.RTT)))
			}
		}
		fmt.Fprintf(w, "%s  %s %s %s %s %s %s\n", ttl, Pad(name, 44), Pad(C(gray, asLabel(app.ASOf(rs))), 24),
			Pad(loc, 22), Pad(src, 8), strings.Join(rtts, " "), strings.Join(flags, " "))
	}
}

// Anomalies lists RTT physics conflicts after the table.
func Anomalies(w io.Writer, r *trace.Result) {
	first := true
	for _, h := range r.Hops {
		for i := range h.Responders {
			info := app.InfoOf(&h.Responders[i])
			if info == nil || !info.RTTAnomaly {
				continue
			}
			if first {
				fmt.Fprintln(w, C(bold, "\nRTT physics"))
				first = false
			}
			fmt.Fprintf(w, "  %s %-16s %s → using %s\n", C(red, "⚠"), h.Responders[i].IP, info.Anomaly, SourceBadge(info.Source))
		}
	}
}

// Summary prints the final line of a trace.
func Summary(w io.Writer, r *trace.Result) {
	st := C(green, "reached")
	if !r.Reached {
		st = C(red, "not reached")
	}
	last := 0.0
	if len(r.Hops) > 0 {
		last = r.Hops[len(r.Hops)-1].AvgRTT()
	}
	path := store.FormatASPath(store.ASPath(r))
	fmt.Fprintf(w, "\n%s %s in %d hops, %s ms, %s probes · AS path %s", st, r.Target, len(r.Hops), FmtRTT(last),
		strings.ToUpper(string(r.Protocol)), path)
	if r.ID != "" {
		fmt.Fprintf(w, " · saved %s", C(cyan, r.ID))
	}
	fmt.Fprintln(w)
}

// Title prints the trace header line.
func Title(w io.Writer, r *trace.Result, iface string) {
	proto := strings.ToUpper(string(r.Protocol))
	if r.Port > 0 {
		proto += fmt.Sprintf(":%d", r.Port)
	}
	extra := r.Privilege + " socket"
	if iface != "" {
		extra += ", via " + iface
	}
	fmt.Fprintf(w, "%s %s %s %s\n", C(bold, "traced"), C(cyan, r.Target), C(gray, "("+r.TargetIP+")"), C(gray, proto+" · "+extra))
}

// Whois prints a WHOIS/RDAP + DNS report.
func Whois(w io.Writer, rep *whois.Report) {
	if rep == nil {
		return
	}
	kv := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "  %s %s\n", C(gray, Pad(k, 12)), v)
		}
	}
	if d := rep.Domain; d != nil {
		fmt.Fprintf(w, "\n%s %s %s\n", C(bold, "Domain"), C(cyan, d.Domain), C(gray, "["+d.Source+" "+d.Server+"]"))
		kv("registrar", d.Registrar)
		kv("registrant", d.Registrant)
		kv("created", shortDate(d.Created))
		exp := shortDate(d.Expires)
		if t, err := time.Parse(time.RFC3339, d.Expires); err == nil {
			days := int(time.Until(t).Hours() / 24)
			col := green
			if days < 30 {
				col = red
			} else if days < 90 {
				col = yellow
			}
			exp += C(col, fmt.Sprintf(" (in %d days)", days))
		}
		kv("expires", exp)
		kv("updated", shortDate(d.Updated))
		kv("nameservers", strings.Join(d.Nameservers, ", "))
		kv("status", strings.Join(d.Status, ", "))
		kv("dnssec", d.DNSSEC)
	}
	if n := rep.DNS; n != nil {
		fmt.Fprintf(w, "\n%s\n", C(bold, "DNS"))
		kv("CNAME", n.CNAME)
		kv("A", strings.Join(n.A, ", "))
		kv("AAAA", strings.Join(n.AAAA, ", "))
		kv("NS", strings.Join(n.NS, ", "))
		kv("MX", strings.Join(n.MX, ", "))
	}
	for _, ip := range rep.IPs {
		fmt.Fprintf(w, "\n%s %s %s\n", C(bold, "IP"), C(cyan, ip.IP), C(gray, "["+ip.Source+"]"))
		if ip.ASN > 0 {
			kv("ASN", fmt.Sprintf("AS%d %s", ip.ASN, ip.ASName))
		}
		kv("prefix", ip.ASPrefix)
		kv("netname", ip.NetName)
		kv("org", ip.Org)
		kv("country", ip.Country)
		kv("range", ip.Range)
		kv("cidr", strings.Join(ip.CIDRs, ", "))
		kv("RIR", ip.RIR)
		kv("abuse", ip.Abuse)
		kv("geofeed", ip.Geofeed)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "  %s %s\n", C(yellow, "!"), e)
	}
}

func shortDate(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2006-01-02")
	}
	return s
}

// SNIStep prints one TTL-scan step.
func SNIStep(w io.Writer, s *trace.SNIStep) {
	col := map[string]string{trace.SNITTLExceeded: gray, trace.SNIServerHello: green, trace.SNIAlert: green,
		trace.SNIReset: red, trace.SNIClosed: red, trace.SNITimeout: yellow, trace.SNIConnectFail: red}[s.Outcome]
	router := s.Router
	if router == "" {
		router = "—"
	}
	rtt := ""
	if s.RTT > 0 {
		rtt = FmtRTT(s.RTT) + " ms"
	}
	fmt.Fprintf(w, "  ttl %2d  %s %s %s %s\n", s.TTL, Pad(C(col, s.Outcome), 14), Pad(router, 18), Pad(rtt, 10), C(gray, s.Detail))
}

// SNI prints the SNI verdict.
func SNI(w io.Writer, r *trace.SNIResult) {
	if r == nil {
		return
	}
	col := green
	if r.Verdict != "ok" {
		col = red
	}
	fmt.Fprintf(w, "\n%s %s → %s:%d\n", C(bold, "SNI"), C(cyan, r.SNI), r.IP, r.Port)
	att := func(name string, a trace.SNIAttempt) {
		c := red
		if a.Outcome == trace.SNIServerHello || a.Outcome == trace.SNIAlert {
			c = green
		}
		fmt.Fprintf(w, "  %s %-22s %s %s %s\n", C(gray, Pad(name, 8)), a.SNI, Pad(C(c, a.Outcome), 14), Pad(FmtRTT(a.RTT)+" ms", 10), C(gray, a.Detail))
	}
	att("target", r.Target)
	att("control", r.Control)
	if r.ServerTTL > 0 || r.DestTTL > 0 {
		fmt.Fprintf(w, "  %s server is %d hops away", C(gray, Pad("path", 8)), r.DestTTL)
		if r.ServerTTL > 0 {
			fmt.Fprintf(w, ", TLS answer at TTL %d", r.ServerTTL)
		}
		if r.BlockTTL > 0 {
			fmt.Fprintf(w, ", interference at TTL %d", r.BlockTTL)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  %s %s\n", C(gray, Pad("verdict", 8)), C(col, strings.ToUpper(r.Verdict))+" — "+r.Summary)
}

// History prints the stored traces.
func History(w io.Writer, list []store.Summary) {
	if len(list) == 0 {
		fmt.Fprintln(w, "no traces yet — run `traced <target>`")
		return
	}
	fmt.Fprintln(w, C(dim, fmt.Sprintf("%3s  %-18s %-17s %-28s %-9s %5s %9s", "#", "id", "when", "target", "proto", "hops", "rtt")))
	for i, s := range list {
		st := C(green, "✓")
		if !s.Reached {
			st = C(red, "✗")
		}
		proto := string(s.Protocol)
		if s.Port > 0 {
			proto += fmt.Sprintf(":%d", s.Port)
		}
		fmt.Fprintf(w, "%3d  %s %-17s %s %-9s %5d %9s %s\n", i+1, Pad(C(cyan, s.ID), 18), s.Started.Local().Format("2006-01-02 15:04"),
			Pad(s.Target, 28), proto, s.Hops, FmtRTT(s.RTT)+" ms", st)
	}
}

// Diff prints a hop-by-hop comparison.
func Diff(w io.Writer, d *store.Diff) {
	fmt.Fprintf(w, "%s %s (%s) ↔ %s (%s)\n\n", C(bold, "diff"), C(cyan, d.IDA), d.A.Target, C(cyan, d.IDB), d.B.Target)
	fmt.Fprintln(w, C(dim, fmt.Sprintf("%3s  %-34s %-34s %8s %8s %8s", "#", "A", "B", "rtt A", "rtt B", "Δ")))
	for _, h := range d.Hops {
		col := map[string]string{"same": gray, "ecmp": cyan, "changed": yellow, "added": green, "removed": red, "lost": yellow}[h.Status]
		a, b := strings.Join(h.A, ","), strings.Join(h.B, ",")
		if a == "" {
			a = "*"
		}
		if b == "" {
			b = "*"
		}
		if h.ASA != 0 && h.ASA != h.ASB {
			a += fmt.Sprintf(" AS%d", h.ASA)
		}
		if h.ASB != 0 && h.ASA != h.ASB {
			b += fmt.Sprintf(" AS%d", h.ASB)
		}
		delta := ""
		if h.Delta != 0 {
			dc := green
			if h.Delta > 5 {
				dc = red
			} else if h.Delta > 1 {
				dc = yellow
			}
			delta = C(dc, fmt.Sprintf("%+.1f", h.Delta))
		}
		fmt.Fprintf(w, "%3d  %s %s %8s %8s %8s  %s\n", h.TTL, Pad(a, 34), Pad(b, 34), FmtRTT(h.RTTA), FmtRTT(h.RTTB), delta, C(col, h.Status))
	}
	fmt.Fprintf(w, "\nAS path A  %s\nAS path B  %s\n", store.FormatASPath(d.ASPathA), store.FormatASPath(d.ASPathB))
	fmt.Fprintln(w, C(bold, d.Summary))
}

// Note prints an informational line.
func Note(w io.Writer, s string) { fmt.Fprintln(w, C(yellow, "› ")+C(gray, s)) }
