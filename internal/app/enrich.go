package app

import (
	"context"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/asn"
	"github.com/PalMeany/traced-cli/internal/feeds"
	"github.com/PalMeany/traced-cli/internal/rep"
	"github.com/PalMeany/traced-cli/internal/trace"
)

// SegmentCables are the cable hints for one long hop-to-hop segment.
type SegmentCables struct {
	FromTTL int               `json:"from_ttl"`
	ToTTL   int               `json:"to_ttl"`
	From    string            `json:"from"`
	To      string            `json:"to"`
	Km      float64           `json:"km"`
	Cables  []feeds.CableHint `json:"cables"`
}

// Limits of the per-trace enrichment.
const (
	maxEnrichASNs = 14
	maxPoPs       = 40
	enrichWait    = 12 * time.Second // after the trace ends
)

// enricher profiles every AS met on the path while the trace runs.
type enricher struct {
	ctx     context.Context
	mu      sync.Mutex
	started map[int]bool
	reports map[int]*asn.Report
	reps    map[int]*rep.Report
	wg      sync.WaitGroup
	sem     chan struct{}
	emit    func(trace.Event)
}

func newEnricher(ctx context.Context, emit func(trace.Event)) *enricher {
	return &enricher{ctx: ctx, started: map[int]bool{}, reports: map[int]*asn.Report{}, reps: map[int]*rep.Report{},
		sem: make(chan struct{}, 4), emit: emit}
}

// add starts the lookups for the ASNs of a hop (once per AS).
func (e *enricher) add(h *trace.Hop) {
	for i := range h.Responders {
		a := ASOf(&h.Responders[i])
		if a == nil || a.ASN == 0 || a.ASN >= 64512 && a.ASN <= 65535 || a.ASN >= 4200000000 {
			continue
		}
		e.mu.Lock()
		if e.started[a.ASN] || len(e.started) >= maxEnrichASNs {
			e.mu.Unlock()
			continue
		}
		e.started[a.ASN] = true
		e.mu.Unlock()
		e.wg.Add(1)
		go func(n int) {
			defer e.wg.Done()
			select {
			case e.sem <- struct{}{}:
			case <-e.ctx.Done():
				return
			}
			defer func() { <-e.sem }()
			r := asn.Profile(e.ctx, n, asn.Options{Prefixes: true, Timeout: 10 * time.Second})
			var rp *rep.Report
			if r.Routing != nil && r.Routing.CountV4+r.Routing.CountV6 > 0 {
				o := rep.Options{PrefixesV4: r.Routing.V4, PrefixesV6: r.Routing.V6}
				rp = rep.CheckASN(e.ctx, n, o)
			} else {
				rp = rep.CheckASN(e.ctx, n, rep.Options{NoNetwork: true, PrefixesV4: []string{}})
			}
			e.mu.Lock()
			e.reports[n] = r
			e.reps[n] = rp
			e.mu.Unlock()
		}(a.ASN)
	}
}

// finish waits (bounded) and condenses the profiles.
func (e *enricher) finish(hops []trace.Hop) map[string]*asn.Brief {
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(enrichWait):
	case <-e.ctx.Done():
	}
	var near [][2]float64
	for i := range hops {
		for j := range hops[i].Responders {
			if g := InfoOf(&hops[i].Responders[j]); g != nil && g.Located {
				near = append(near, [2]float64{g.Lat, g.Lon})
			}
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.reports) == 0 {
		return nil
	}
	out := map[string]*asn.Brief{}
	for n, r := range e.reports {
		b := asn.BriefOf(r, near, maxPoPs)
		if rp := e.reps[n]; rp != nil {
			b.Rep, b.RepScore = rp.Verdict, rp.Score
			for _, s := range rp.Sources {
				if (s.Status == rep.StListed || s.Status == rep.StInfo) && s.Summary != "" {
					b.RepNotes = append(b.RepNotes, s.Title+": "+s.Summary)
				}
			}
		}
		out[strconv.Itoa(n)] = b
	}
	return out
}

// CableHints suggests submarine cables for long segments between consecutive
// located hops (first responder of each hop). Only the cached cable map is
// used; nothing is downloaded during a trace.
func CableHints(db *feeds.CableDB, hops []trace.Hop) []SegmentCables {
	if db == nil {
		return nil
	}
	type pt struct {
		ttl      int
		lat, lon float64
		label    string
	}
	var pts []pt
	for i := range hops {
		if len(hops[i].Responders) == 0 {
			continue
		}
		g := InfoOf(&hops[i].Responders[0])
		if g == nil || !g.Located || g.Private {
			continue
		}
		pts = append(pts, pt{hops[i].TTL, g.Lat, g.Lon, g.Label()})
	}
	var out []SegmentCables
	for i := 1; i < len(pts); i++ {
		a, b := pts[i-1], pts[i]
		km := feeds.HaversineKm(a.lat, a.lon, b.lat, b.lon)
		if km < feeds.MinSuggestKm {
			continue
		}
		hs := db.Suggest(a.lat, a.lon, b.lat, b.lon, 3)
		if len(hs) == 0 {
			continue
		}
		out = append(out, SegmentCables{FromTTL: a.ttl, ToTTL: b.ttl, From: a.label, To: b.label, Km: math.Round(km), Cables: hs})
		if len(out) >= 10 {
			break
		}
	}
	return out
}
