// Package mtr implements the live MTR view: repeated single-probe rounds,
// per-hop statistics and a raw-ANSI terminal UI.
package mtr

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/geo"
	"github.com/PalMeany/traced-cli/internal/store"
	"github.com/PalMeany/traced-cli/internal/trace"
	"github.com/PalMeany/traced-cli/internal/ui"
	"golang.org/x/term"
)

// Options of the MTR session.
type Options struct {
	Trace    trace.Options
	Geo      bool
	GeoOpts  geo.Options
	Interval time.Duration
	Numeric  bool
	Note     string
	OpenMap  func(*trace.Result) (string, error)
}

const histLen = 48

// HopStats accumulates per-TTL statistics.
type HopStats struct {
	TTL      int
	Sent     int
	Recv     int
	Last     float64
	Best     float64
	Worst    float64
	mean, m2 float64   // Welford
	Hist     []float64 // -1 = lost
	IPs      map[string]int
	RTTs     map[string][]float64
	Final    bool
	MPLS     []trace.MPLSLabel
}

func newHop(ttl int) *HopStats {
	return &HopStats{TTL: ttl, IPs: map[string]int{}, RTTs: map[string][]float64{}}
}

// Add records one probe.
func (h *HopStats) Add(p trace.Probe) {
	h.Sent++
	if p.Lost || p.IP == "" {
		h.push(-1)
		return
	}
	h.Recv++
	h.IPs[p.IP]++
	r := h.RTTs[p.IP]
	if len(r) >= 200 {
		r = r[1:]
	}
	h.RTTs[p.IP] = append(r, p.RTT)
	if p.Final {
		h.Final = true
	}
	if len(p.MPLS) > 0 {
		h.MPLS = p.MPLS
	}
	h.Last = p.RTT
	if h.Best == 0 || p.RTT < h.Best {
		h.Best = p.RTT
	}
	if p.RTT > h.Worst {
		h.Worst = p.RTT
	}
	d := p.RTT - h.mean
	h.mean += d / float64(h.Recv)
	h.m2 += d * (p.RTT - h.mean)
	h.push(p.RTT)
}

func (h *HopStats) push(v float64) {
	h.Hist = append(h.Hist, v)
	if len(h.Hist) > histLen {
		h.Hist = h.Hist[len(h.Hist)-histLen:]
	}
}

// Loss in percent.
func (h *HopStats) Loss() float64 {
	if h.Sent == 0 {
		return 0
	}
	return 100 * float64(h.Sent-h.Recv) / float64(h.Sent)
}

// Avg RTT.
func (h *HopStats) Avg() float64 { return h.mean }

// StDev of RTT.
func (h *HopStats) StDev() float64 {
	if h.Recv < 2 {
		return 0
	}
	return math.Sqrt(h.m2 / float64(h.Recv-1))
}

// Primary is the most frequent responder.
func (h *HopStats) Primary() string {
	best, n := "", -1
	for ip, c := range h.IPs {
		if c > n || c == n && ip < best {
			best, n = ip, c
		}
	}
	return best
}

var sparks = []rune("▁▂▃▄▅▆▇█")

// Spark renders the RTT history.
func Spark(hist []float64, width int) string {
	if len(hist) > width {
		hist = hist[len(hist)-width:]
	}
	lo, hi := math.MaxFloat64, 0.0
	for _, v := range hist {
		if v < 0 {
			continue
		}
		lo = math.Min(lo, v)
		hi = math.Max(hi, v)
	}
	var b strings.Builder
	for i := 0; i < width-len(hist); i++ {
		b.WriteRune(' ')
	}
	for _, v := range hist {
		if v < 0 {
			b.WriteString(ui.C("\x1b[31m", "×"))
			continue
		}
		idx := 0
		if hi > lo {
			idx = int((v - lo) / (hi - lo) * float64(len(sparks)-1))
		}
		b.WriteString(ui.C(ui.RTTColor(v), string(sparks[idx])))
	}
	return b.String()
}

// model is the shared MTR state.
type model struct {
	mu      sync.Mutex
	hops    map[int]*HopStats
	maxTTL  int // final TTL (0 = unknown)
	rounds  int
	paused  bool
	numeric bool
	status  string
	geoData map[string]*geo.IPData
	pending map[string]bool
	started time.Time
	dst     string
	target  string
	proto   string
	priv    string
	iface   string
}

func (m *model) reset() {
	m.hops = map[int]*HopStats{}
	m.maxTTL = 0
	m.rounds = 0
	m.started = time.Now()
}

// snapshot converts stats into a trace.Result (used for the map and geo validation).
func (m *model) snapshot() *trace.Result {
	r := &trace.Result{Target: m.target, TargetIP: m.dst, Protocol: trace.Protocol(m.proto), Started: m.started, Privilege: m.priv}
	var ttls []int
	for t := range m.hops {
		if m.maxTTL == 0 || t <= m.maxTTL {
			ttls = append(ttls, t)
		}
	}
	sort.Ints(ttls)
	for _, t := range ttls {
		hs := m.hops[t]
		h := trace.Hop{TTL: t, Sent: hs.Sent, Received: hs.Recv, Final: hs.Final}
		var ips []string
		for ip := range hs.IPs {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { return hs.IPs[ips[i]] > hs.IPs[ips[j]] })
		for _, ip := range ips {
			rs := trace.Responder{IP: ip, RTTs: append([]float64(nil), hs.RTTs[ip]...), MPLS: hs.MPLS}
			if hs.Final && ip == m.dst {
				rs.Final = true
			}
			h.Responders = append(h.Responders, rs)
			for _, v := range hs.RTTs[ip] {
				h.Probes = append(h.Probes, trace.Probe{TTL: t, IP: ip, RTT: v})
			}
		}
		for i := 0; i < hs.Sent-hs.Recv && i < 10; i++ {
			h.Probes = append(h.Probes, trace.Probe{TTL: t, Lost: true})
		}
		r.Hops = append(r.Hops, h)
		if hs.Final {
			r.Reached = true
		}
	}
	return r
}

// Run starts the interactive MTR.
func Run(ctx context.Context, o Options) error {
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	sess, err := trace.NewSession(o.Trace)
	if err != nil {
		return err
	}
	defer sess.Close()
	var res *geo.Resolver
	if o.Geo {
		res, err = geo.New(o.GeoOpts)
		if err != nil {
			return err
		}
		defer res.Close()
	}
	m := &model{numeric: o.Numeric, geoData: map[string]*geo.IPData{}, pending: map[string]bool{},
		dst: sess.Dst.String(), target: o.Trace.Target, proto: string(sess.Opts.Protocol), priv: sess.Privilege, iface: o.Trace.Interface}
	m.reset()
	if o.Note != "" {
		m.status = o.Note
	}

	fd := int(os.Stdin.Fd())
	interactive := term.IsTerminal(fd) && term.IsTerminal(int(os.Stdout.Fd()))
	var restore func()
	if interactive {
		old, err := term.MakeRaw(fd)
		if err == nil {
			restore = func() { term.Restore(fd, old) }
		}
		fmt.Print("\x1b[?1049h\x1b[?25l")
	}
	defer func() {
		if interactive {
			fmt.Print("\x1b[?25h\x1b[?1049l")
		}
		if restore != nil {
			restore()
		}
		// print a final static report
		m.mu.Lock()
		m.render(os.Stdout, 0, 0, false)
		m.mu.Unlock()
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// keyboard
	if interactive {
		go func() {
			rd := bufio.NewReader(os.Stdin)
			for {
				b, err := rd.ReadByte()
				if err != nil {
					return
				}
				m.mu.Lock()
				switch b {
				case 'q', 'Q', 3, 27:
					cancel()
				case 'p', 'P', ' ':
					m.paused = !m.paused
					m.status = map[bool]string{true: "paused", false: "resumed"}[m.paused]
				case 'r', 'R':
					m.reset()
					m.status = "statistics reset"
				case 'n', 'N':
					m.numeric = !m.numeric
				case 'm', 'M':
					if o.OpenMap != nil {
						snap := m.snapshot()
						m.applyGeo(snap, res)
						m.status = "opening map…"
						go func() {
							url, err := o.OpenMap(snap)
							m.mu.Lock()
							if err != nil {
								m.status = "map: " + err.Error()
							} else {
								m.status = "map: " + url
							}
							m.mu.Unlock()
						}()
					}
				}
				m.mu.Unlock()
			}
		}()
	}

	// probing loop
	go func() {
		for ctx.Err() == nil {
			m.mu.Lock()
			paused := m.paused
			m.mu.Unlock()
			t0 := time.Now()
			if !paused {
				_, _ = sess.Trace(ctx, func(e trace.Event) {
					if e.Type != "hop" {
						return
					}
					m.mu.Lock()
					hs := m.hops[e.Hop.TTL]
					if hs == nil {
						hs = newHop(e.Hop.TTL)
						m.hops[e.Hop.TTL] = hs
					}
					for _, p := range e.Hop.Probes {
						hs.Add(p)
						if !p.Lost && p.IP != "" && res != nil && m.geoData[p.IP] == nil && !m.pending[p.IP] {
							m.pending[p.IP] = true
							ip := p.IP
							go func() {
								d := res.Gather(ctx, []string{ip})
								m.mu.Lock()
								for k, v := range d {
									m.geoData[k] = v
								}
								delete(m.pending, ip)
								m.mu.Unlock()
							}()
						}
					}
					if e.Hop.Final && (m.maxTTL == 0 || e.Hop.TTL < m.maxTTL) {
						m.maxTTL = e.Hop.TTL
					}
					m.mu.Unlock()
				})
				m.mu.Lock()
				m.rounds++
				m.mu.Unlock()
			}
			if d := o.Interval - time.Since(t0); d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
				}
			}
		}
	}()

	if !interactive {
		<-ctx.Done()
		return nil
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			w, h, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				w, h = 120, 40
			}
			var sb strings.Builder
			sb.WriteString("\x1b[H")
			m.mu.Lock()
			m.render(&sb, w, h, true)
			m.mu.Unlock()
			sb.WriteString("\x1b[J")
			os.Stdout.WriteString(strings.ReplaceAll(sb.String(), "\n", "\x1b[K\r\n"))
		}
	}
}

// applyGeo runs the path validation over the current snapshot (lock held).
func (m *model) applyGeo(r *trace.Result, res *geo.Resolver) {
	if res == nil {
		return
	}
	geo.Validate(r.Hops, m.geoData, res.Origin())
}

type writer interface{ WriteString(string) (int, error) }

func (m *model) render(w writer, width, height int, live bool) {
	snap := m.snapshot()
	if len(m.geoData) > 0 {
		geo.Validate(snap.Hops, m.geoData, nil)
	}
	byTTL := map[int]*trace.Hop{}
	for i := range snap.Hops {
		byTTL[snap.Hops[i].TTL] = &snap.Hops[i]
	}
	if width <= 0 {
		width = 160
	}
	b := func(s string) string { return ui.C("\x1b[1m", s) }
	g := func(s string) string { return ui.C("\x1b[90m", s) }
	state := "running"
	if m.paused {
		state = ui.C("\x1b[33m", "paused")
	}
	head := fmt.Sprintf("%s %s %s  %s  round %d  %s", b("traced mtr"), ui.C("\x1b[36m", m.target), g("("+m.dst+")"),
		g(strings.ToUpper(m.proto)+" · "+m.priv+ifaceNote(m.iface)), m.rounds, state)
	w.WriteString(head + "\n")
	if live {
		w.WriteString(g("keys: q quit · p pause · r reset · n names · m map") + "\n")
	}
	w.WriteString("\n")
	sparkW := 20
	hostW := width - (4 + 7 + 5 + 7*5 + 3 + sparkW + 24 + 22 + 8)
	if hostW < 18 {
		hostW = 18
	}
	if hostW > 46 {
		hostW = 46
	}
	hdr := fmt.Sprintf("%3s  %s %6s %4s %6s %6s %6s %6s %6s  %s %s %s %s", "#", ui.Pad("host", hostW), "loss%", "snt", "last", "avg", "best", "wrst", "stdev",
		ui.Pad("history", sparkW), ui.Pad("asn", 22), ui.Pad("city / ixp", 20), "geo")
	w.WriteString(ui.C("\x1b[2m", hdr) + "\n")
	var ttls []int
	for t := range m.hops {
		if m.maxTTL == 0 || t <= m.maxTTL {
			ttls = append(ttls, t)
		}
	}
	sort.Ints(ttls)
	lines := 0
	for _, t := range ttls {
		if live && height > 0 && lines > height-7 {
			break
		}
		hs := m.hops[t]
		ip := hs.Primary()
		name := ip
		var rs *trace.Responder
		if hop := byTTL[t]; hop != nil {
			for i := range hop.Responders {
				if hop.Responders[i].IP == ip {
					rs = &hop.Responders[i]
				}
			}
		}
		if ip == "" {
			name = g("???")
		} else if !m.numeric && rs != nil && rs.Host != "" {
			name = rs.Host
		}
		if len(hs.IPs) > 1 {
			name = ui.Trunc(name, hostW-4) + ui.C("\x1b[36m", fmt.Sprintf(" ⑂%d", len(hs.IPs)))
		}
		loss := hs.Loss()
		lc := "\x1b[32m"
		if loss > 30 {
			lc = "\x1b[31m"
		} else if loss > 0 {
			lc = "\x1b[33m"
		}
		asn, loc, src := "", "", ""
		if rs != nil {
			if a := app.ASOf(rs); a != nil {
				nm := a.Name
				if i := strings.IndexAny(nm, " ,"); i > 0 {
					nm = nm[:i]
				}
				asn = fmt.Sprintf("AS%d %s", a.ASN, nm)
			}
			if info := app.InfoOf(rs); info != nil {
				loc = info.Label()
				if info.IXP != nil {
					loc = info.IXP.Name
				}
				src = ui.SourceBadge(info.Source)
				if info.RTTAnomaly {
					src += ui.C("\x1b[31m", "⚠")
				}
			}
		}
		f := func(v float64) string {
			if hs.Recv == 0 {
				return g("     -")
			}
			return ui.C(ui.RTTColor(v), fmt.Sprintf("%6s", ui.FmtRTT(v)))
		}
		line := fmt.Sprintf("%3d  %s %s %4d %s %s %s %s %6s  %s %s %s %s",
			t, ui.Pad(name, hostW), ui.C(lc, fmt.Sprintf("%5.1f%%", loss)), hs.Sent, f(hs.Last), f(hs.Avg()), f(hs.Best), f(hs.Worst),
			fmt.Sprintf("%.1f", hs.StDev()), Spark(hs.Hist, sparkW), ui.Pad(g(asn), 22), ui.Pad(loc, 20), src)
		w.WriteString(line + "\n")
		lines++
	}
	if m.status != "" {
		w.WriteString("\n" + ui.C("\x1b[33m", "› ") + g(m.status) + "\n")
	}
	if !live {
		w.WriteString(g(fmt.Sprintf("%d rounds, %s, AS path %s", m.rounds, time.Since(m.started).Round(time.Second), store.FormatASPath(store.ASPath(snap)))) + "\n")
	}
}

func ifaceNote(i string) string {
	if i == "" {
		return ""
	}
	return " · via " + i
}
