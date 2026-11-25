package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/PalMeany/traced-cli/internal/trace"
)

// HopDiff compares one TTL of two traces.
type HopDiff struct {
	TTL    int      `json:"ttl"`
	A      []string `json:"a"`
	B      []string `json:"b"`
	ASA    int      `json:"as_a,omitempty"`
	ASB    int      `json:"as_b,omitempty"`
	RTTA   float64  `json:"rtt_a"`
	RTTB   float64  `json:"rtt_b"`
	Delta  float64  `json:"delta_ms"`
	Status string   `json:"status"` // same | changed | ecmp | added | removed | lost
	LossA  float64  `json:"loss_a"`
	LossB  float64  `json:"loss_b"`
}

// Diff is the comparison of two traces.
type Diff struct {
	A, B          Summary   `json:"-"`
	IDA           string    `json:"a"`
	IDB           string    `json:"b"`
	Hops          []HopDiff `json:"hops"`
	ASPathA       []int     `json:"as_path_a"`
	ASPathB       []int     `json:"as_path_b"`
	ASPathChanged bool      `json:"as_path_changed"`
	FinalA        float64   `json:"final_rtt_a"`
	FinalB        float64   `json:"final_rtt_b"`
	FinalDelta    float64   `json:"final_delta_ms"`
	Changed       int       `json:"changed_hops"`
	Summary       string    `json:"summary"`
}

// ASNOf extracts the origin ASN of a responder (works for live and decoded traces).
func ASNOf(r *trace.Responder) int {
	if r == nil || r.Network == nil {
		return 0
	}
	b, err := json.Marshal(r.Network)
	if err != nil {
		return 0
	}
	var v struct {
		ASN int `json:"asn"`
	}
	_ = json.Unmarshal(b, &v)
	return v.ASN
}

// ASPath is the de-duplicated sequence of origin ASNs along the path.
func ASPath(r *trace.Result) []int {
	var p []int
	for i := range r.Hops {
		as := ASNOf(r.Hops[i].Primary())
		if as == 0 {
			continue
		}
		if len(p) == 0 || p[len(p)-1] != as {
			p = append(p, as)
		}
	}
	return p
}

func ipSet(h *trace.Hop) []string {
	if h == nil {
		return nil
	}
	var s []string
	for _, r := range h.Responders {
		s = append(s, r.IP)
	}
	sort.Strings(s)
	return s
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compare builds a hop-by-hop diff of two traces.
func Compare(a, b *trace.Result) *Diff {
	d := &Diff{A: Summarize(a), B: Summarize(b), IDA: a.ID, IDB: b.ID}
	byTTL := func(r *trace.Result) map[int]*trace.Hop {
		m := map[int]*trace.Hop{}
		for i := range r.Hops {
			m[r.Hops[i].TTL] = &r.Hops[i]
		}
		return m
	}
	ma, mb := byTTL(a), byTTL(b)
	maxT := 0
	for t := range ma {
		if t > maxT {
			maxT = t
		}
	}
	for t := range mb {
		if t > maxT {
			maxT = t
		}
	}
	for t := 1; t <= maxT; t++ {
		ha, hb := ma[t], mb[t]
		hd := HopDiff{TTL: t, A: ipSet(ha), B: ipSet(hb)}
		if ha != nil {
			hd.RTTA, hd.LossA, hd.ASA = ha.AvgRTT(), ha.Loss(), ASNOf(ha.Primary())
		}
		if hb != nil {
			hd.RTTB, hd.LossB, hd.ASB = hb.AvgRTT(), hb.Loss(), ASNOf(hb.Primary())
		}
		if hd.RTTA > 0 && hd.RTTB > 0 {
			hd.Delta = hd.RTTB - hd.RTTA
		}
		switch {
		case ha == nil:
			hd.Status = "added"
		case hb == nil:
			hd.Status = "removed"
		case len(hd.A) == 0 || len(hd.B) == 0:
			hd.Status = "lost"
			if len(hd.A) == 0 && len(hd.B) == 0 {
				hd.Status = "same"
			}
		case strings.Join(hd.A, ",") == strings.Join(hd.B, ","):
			hd.Status = "same"
		case intersects(hd.A, hd.B):
			hd.Status = "ecmp"
		default:
			hd.Status = "changed"
		}
		if hd.Status == "changed" || hd.Status == "added" || hd.Status == "removed" {
			d.Changed++
		}
		d.Hops = append(d.Hops, hd)
	}
	d.ASPathA, d.ASPathB = ASPath(a), ASPath(b)
	d.ASPathChanged = !equalInts(d.ASPathA, d.ASPathB)
	if len(a.Hops) > 0 {
		d.FinalA = a.Hops[len(a.Hops)-1].AvgRTT()
	}
	if len(b.Hops) > 0 {
		d.FinalB = b.Hops[len(b.Hops)-1].AvgRTT()
	}
	if d.FinalA > 0 && d.FinalB > 0 {
		d.FinalDelta = d.FinalB - d.FinalA
	}
	var parts []string
	if d.Changed == 0 {
		parts = append(parts, "same routers")
	} else {
		parts = append(parts, fmt.Sprintf("%d hop(s) changed", d.Changed))
	}
	if d.ASPathChanged {
		parts = append(parts, "AS path changed: "+FormatASPath(d.ASPathA)+" → "+FormatASPath(d.ASPathB))
	} else if len(d.ASPathA) > 0 {
		parts = append(parts, "AS path unchanged ("+FormatASPath(d.ASPathA)+")")
	}
	if d.FinalA > 0 && d.FinalB > 0 {
		parts = append(parts, fmt.Sprintf("end-to-end %+.1f ms", d.FinalDelta))
	}
	d.Summary = strings.Join(parts, "; ")
	return d
}

// FormatASPath renders "AS1 → AS2".
func FormatASPath(p []int) string {
	if len(p) == 0 {
		return "—"
	}
	s := make([]string, len(p))
	for i, a := range p {
		s[i] = fmt.Sprintf("AS%d", a)
	}
	return strings.Join(s, " → ")
}
