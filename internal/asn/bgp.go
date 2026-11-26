package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
	"github.com/PalMeany/traced-cli/internal/feeds"
)

// BGPViewURL is the optional fallback endpoint for prefix upstreams (overridable in tests).
var BGPViewURL = "https://api.bgpview.io"

// PrefixUpstream is an upstream AS through which a prefix is seen announced in global BGP.
type PrefixUpstream struct {
	ASN        int     `json:"asn"`
	Name       string  `json:"name,omitempty"`
	Peers      int     `json:"peers"`
	Pct        float64 `json:"pct"`
	SamplePath []int   `json:"sample_path,omitempty"`
}

// HistoryEvent is one origin announcement period of a prefix.
type HistoryEvent struct {
	ASN    int    `json:"asn"`
	Name   string `json:"name,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Start  string `json:"start"`
	End    string `json:"end,omitempty"`
	Active bool   `json:"active,omitempty"`
}

// ASNHistoryPoint is one compact snapshot of an ASN's announced prefixes over time.
type ASNHistoryPoint struct {
	Time     string `json:"time"`
	Prefixes int    `json:"prefixes"`
}

// ASNHistory summarises an ASN's BGP announcement timeline.
type ASNHistory struct {
	FirstSeen string            `json:"first_seen,omitempty"`
	LastSeen  string            `json:"last_seen,omitempty"`
	Current   int               `json:"current,omitempty"`
	Peak      int               `json:"peak,omitempty"`
	Points    []ASNHistoryPoint `json:"points,omitempty"`
}

// PrefixBGP describes how a prefix is announced in BGP: origin, direct upstreams, and history.
type PrefixBGP struct {
	Prefix     string           `json:"prefix"`
	OriginASN  int              `json:"origin_asn,omitempty"`
	OriginName string           `json:"origin_name,omitempty"`
	Upstreams  []PrefixUpstream `json:"upstreams,omitempty"`
	RISPeers   int              `json:"ris_peers,omitempty"`
	History    []HistoryEvent   `json:"history,omitempty"`
	Changes    int              `json:"changes,omitempty"` // distinct origins or re-announcements
	Source     string           `json:"source,omitempty"`
	Cached     bool             `json:"cached,omitempty"`
}

func ripeGetResource(ctx context.Context, call, resource, extraQuery string, ttl time.Duration, offline bool, v any) (bool, error) {
	key := call + "/" + strings.ReplaceAll(resource, "/", "_")
	if extraQuery != "" {
		key += "?" + extraQuery
	}
	var raw json.RawMessage
	if cache.Get("ripestat", key, &raw) {
		return true, json.Unmarshal(raw, v)
	}
	if offline {
		return false, errSkip("offline")
	}
	var x json.RawMessage
	u := fmt.Sprintf("%s/%s/data.json?resource=%s&sourceapp=traced-cli", RIPEstatURL, call, url.QueryEscape(resource))
	if extraQuery != "" {
		u += "&" + extraQuery
	}
	if err := do(ctx, "GET", u, nil, nil, &x); err != nil {
		return false, err
	}
	cache.Put("ripestat", key, x, ttl)
	return false, json.Unmarshal(x, v)
}

// ParseLookingGlass extracts the origin AS and direct upstreams (provider-side
// ASes immediately preceding the origin in RIS BGP AS paths) from RIPEstat
// looking-glass JSON.
func ParseLookingGlass(b []byte) (originASN int, upstreams []PrefixUpstream, totalPeers int, err error) {
	var d struct {
		Data struct {
			RRCs []struct {
				RRC   string `json:"rrc"`
				Peers []struct {
					ASNOrigin string `json:"asn_origin"`
					ASPath    string `json:"as_path"`
				} `json:"peers"`
			} `json:"rrcs"`
		} `json:"data"`
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return
	}
	originCounts := map[int]int{}
	type upStat struct {
		peers  int
		sample []int
	}
	upCounts := map[int]*upStat{}
	seenPaths := 0

	for _, rrc := range d.Data.RRCs {
		for _, p := range rrc.Peers {
			path := parseASPath(p.ASPath)
			if len(path) == 0 {
				if n, ok := ParseASN(p.ASNOrigin); ok {
					originCounts[n]++
					seenPaths++
				}
				continue
			}
			seenPaths++
			orig := path[len(path)-1]
			originCounts[orig]++
			// Walk backwards past AS-path prepends to find the direct upstream AS.
			for i := len(path) - 2; i >= 0; i-- {
				if path[i] != orig {
					up := path[i]
					st := upCounts[up]
					if st == nil {
						st = &upStat{sample: dedupPath(path)}
						upCounts[up] = st
					}
					st.peers++
					break
				}
			}
		}
	}
	totalPeers = seenPaths
	bestOrig, bestCnt := 0, 0
	for a, c := range originCounts {
		if c > bestCnt || (c == bestCnt && a < bestOrig) {
			bestOrig, bestCnt = a, c
		}
	}
	originASN = bestOrig
	for a, st := range upCounts {
		pct := 0.0
		if totalPeers > 0 {
			pct = float64(st.peers) * 100 / float64(totalPeers)
		}
		upstreams = append(upstreams, PrefixUpstream{
			ASN:        a,
			Peers:      st.peers,
			Pct:        float64(int(pct*10+0.5)) / 10,
			SamplePath: st.sample,
		})
	}
	sort.Slice(upstreams, func(i, j int) bool {
		if upstreams[i].Peers != upstreams[j].Peers {
			return upstreams[i].Peers > upstreams[j].Peers
		}
		return upstreams[i].ASN < upstreams[j].ASN
	})
	if len(upstreams) > 10 {
		upstreams = upstreams[:10]
	}
	return
}

func parseASPath(s string) []int {
	fields := strings.Fields(s)
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, "{}[](),")
		if n, err := strconv.Atoi(f); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

func dedupPath(p []int) []int {
	var out []int
	for _, n := range p {
		if len(out) == 0 || out[len(out)-1] != n {
			out = append(out, n)
		}
	}
	if len(out) > 8 {
		out = out[len(out)-8:]
	}
	return out
}

// ParseBGPViewPrefix parses api.bgpview.io/prefix/<ip>/<len> as a fallback.
func ParseBGPViewPrefix(b []byte) (originASN int, originName string, upstreams []PrefixUpstream, err error) {
	var d struct {
		Status string `json:"status"`
		Data   struct {
			ASNs []struct {
				ASN             int    `json:"asn"`
				Name            string `json:"name"`
				PrefixUpstreams []struct {
					ASN  int    `json:"asn"`
					Name string `json:"name"`
				} `json:"prefix_upstreams"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return
	}
	if len(d.Data.ASNs) == 0 {
		return
	}
	a := d.Data.ASNs[0]
	originASN, originName = a.ASN, a.Name
	seen := map[int]bool{}
	for _, u := range a.PrefixUpstreams {
		if u.ASN <= 0 || seen[u.ASN] {
			continue
		}
		seen[u.ASN] = true
		upstreams = append(upstreams, PrefixUpstream{ASN: u.ASN, Name: u.Name})
	}
	return
}

// ParsePrefixHistory parses RIPEstat routing-history for a prefix and returns
// compact origin announcement periods (most recent last).
func ParsePrefixHistory(b []byte) (events []HistoryEvent, changes int, err error) {
	var d struct {
		Data struct {
			QueryEnd string `json:"query_endtime"`
			ByOrigin []struct {
				Origin   string `json:"origin"`
				Prefixes []struct {
					Prefix    string `json:"prefix"`
					Timelines []struct {
						Start string `json:"starttime"`
						End   string `json:"endtime"`
					} `json:"timelines"`
				} `json:"prefixes"`
			} `json:"by_origin"`
		} `json:"data"`
	}
	if err = json.Unmarshal(b, &d); err != nil {
		return
	}
	qEnd := shortISO(d.Data.QueryEnd)
	origins := map[int]bool{}
	for _, bo := range d.Data.ByOrigin {
		n, ok := ParseASN(bo.Origin)
		if !ok {
			continue
		}
		origins[n] = true
		// Merge timelines per origin to keep UI compact.
		var minStart, maxEnd string
		var pfx string
		for _, pr := range bo.Prefixes {
			if pfx == "" {
				pfx = pr.Prefix
			}
			for _, tl := range pr.Timelines {
				st := shortISO(tl.Start)
				en := shortISO(tl.End)
				if st != "" && (minStart == "" || st < minStart) {
					minStart = st
				}
				if en != "" && (maxEnd == "" || en > maxEnd) {
					maxEnd = en
				}
			}
		}
		if minStart == "" {
			continue
		}
		active := qEnd != "" && maxEnd >= qEnd
		events = append(events, HistoryEvent{
			ASN:    n,
			Prefix: pfx,
			Start:  minStart,
			End:    maxEnd,
			Active: active,
		})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Start != events[j].Start {
			return events[i].Start < events[j].Start
		}
		return events[i].ASN < events[j].ASN
	})
	if len(events) > 8 {
		events = events[len(events)-8:]
	}
	if len(origins) > 1 {
		changes = len(origins) - 1
	}
	return
}

// ParseASNHistory parses RIPEstat routing-history for an ASN into a compact
// summary of announced prefix counts over time.
func ParseASNHistory(b []byte) (*ASNHistory, error) {
	var d struct {
		Data struct {
			ByOrigin []struct {
				Origin   string `json:"origin"`
				Prefixes []struct {
					Prefix    string `json:"prefix"`
					Timelines []struct {
						Start string `json:"starttime"`
						End   string `json:"endtime"`
					} `json:"timelines"`
				} `json:"prefixes"`
			} `json:"by_origin"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	// Bucket active prefixes by month (YYYY-MM) from timeline boundaries.
	type span struct{ start, end string }
	var spans []span
	var firstSeen, lastSeen string
	for _, bo := range d.Data.ByOrigin {
		for _, pr := range bo.Prefixes {
			for _, tl := range pr.Timelines {
				st, en := shortISO(tl.Start), shortISO(tl.End)
				if st == "" {
					continue
				}
				if firstSeen == "" || st < firstSeen {
					firstSeen = st
				}
				if en != "" && (lastSeen == "" || en > lastSeen) {
					lastSeen = en
				}
				spans = append(spans, span{st, en})
			}
		}
	}
	if len(spans) == 0 {
		return nil, nil
	}
	// Sample up to 6 evenly spaced dates between firstSeen and lastSeen.
	t0, e0 := time.Parse("2006-01-02", firstSeen)
	t1, e1 := time.Parse("2006-01-02", lastSeen)
	h := &ASNHistory{FirstSeen: firstSeen, LastSeen: lastSeen}
	if e0 == nil && e1 == nil && !t1.Before(t0) {
		steps := 6
		dur := t1.Sub(t0)
		if dur < 7*24*time.Hour {
			steps = 2
		}
		for i := 0; i < steps; i++ {
			var tm time.Time
			if steps == 1 {
				tm = t1
			} else {
				tm = t0.Add(time.Duration(int64(dur) * int64(i) / int64(steps-1)))
			}
			ds := tm.Format("2006-01-02")
			cnt := 0
			for _, sp := range spans {
				if sp.start <= ds && (sp.end == "" || sp.end >= ds) {
					cnt++
				}
			}
			if cnt > h.Peak {
				h.Peak = cnt
			}
			if i == steps-1 {
				h.Current = cnt
			}
			h.Points = append(h.Points, ASNHistoryPoint{Time: ds, Prefixes: cnt})
		}
	}
	return h, nil
}

func shortISO(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// NameFromBulk returns the PeeringDB network name for asn if the local bulk
// feed is loaded (no network call).
func NameFromBulk(ctx context.Context, asn int) string {
	places, _ := feeds.PDB(ctx)
	if places == nil || places.Nets == nil {
		return ""
	}
	if n := places.Nets[asn]; n != nil {
		return n.Name
	}
	return ""
}

// EnrichNeighbourNames fills Name on Neighbour entries from the local PeeringDB bulk feed.
func EnrichNeighbourNames(ctx context.Context, ns []Neighbour) {
	if len(ns) == 0 {
		return
	}
	places, _ := feeds.PDB(ctx)
	if places == nil || places.Nets == nil {
		return
	}
	for i := range ns {
		if ns[i].Name == "" {
			if n := places.Nets[ns[i].ASN]; n != nil {
				ns[i].Name = n.Name
			}
		}
	}
}

// LookupPrefix fetches BGP announcement upstreams (RIPEstat looking-glass,
// fallback BGPView) and announcement history (RIPEstat routing-history) for a
// prefix (e.g. "1.1.1.0/24"). Results are cached for 6 hours.
func LookupPrefix(ctx context.Context, prefix string, offline bool) (*PrefixBGP, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, fmt.Errorf("empty prefix")
	}
	var cachedVal PrefixBGP
	if cache.Get("prefix-bgp", prefix, &cachedVal) && cachedVal.Prefix != "" {
		cachedVal.Cached = true
		return &cachedVal, nil
	}
	if offline {
		return nil, errSkip("offline")
	}

	out := &PrefixBGP{Prefix: prefix}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var lgErr error

	// 1. RIPEstat looking-glass for origin + direct upstreams
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var raw json.RawMessage
		_, err := ripeGetResource(c, "looking-glass", prefix, "", 6*time.Hour, offline, &raw)
		if err != nil {
			mu.Lock()
			lgErr = err
			mu.Unlock()
			return
		}
		orig, ups, peers, err := ParseLookingGlass(raw)
		if err != nil {
			mu.Lock()
			lgErr = err
			mu.Unlock()
			return
		}
		mu.Lock()
		out.OriginASN = orig
		out.Upstreams = ups
		out.RISPeers = peers
		out.Source = "ripestat-lg"
		mu.Unlock()
	}()

	// 2. RIPEstat routing-history for announcement history (last 2 years)
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		start := time.Now().UTC().AddDate(-2, 0, 0).Format("2006-01-02")
		var raw json.RawMessage
		_, err := ripeGetResource(c, "routing-history", prefix, "starttime="+start, 12*time.Hour, offline, &raw)
		if err != nil {
			return
		}
		evs, ch, err := ParsePrefixHistory(raw)
		if err != nil {
			return
		}
		mu.Lock()
		out.History = evs
		out.Changes = ch
		mu.Unlock()
	}()

	wg.Wait()

	// Optional BGPView fallback if looking-glass failed or returned no upstreams
	if len(out.Upstreams) == 0 && BGPViewURL != "" {
		c, cancel := context.WithTimeout(ctx, 6*time.Second)
		var raw json.RawMessage
		err := do(c, "GET", BGPViewURL+"/prefix/"+prefix, nil, nil, &raw)
		cancel()
		if err == nil {
			orig, origName, ups, perr := ParseBGPViewPrefix(raw)
			if perr == nil && (orig > 0 || len(ups) > 0) {
				if out.OriginASN == 0 {
					out.OriginASN = orig
				}
				if out.OriginName == "" {
					out.OriginName = origName
				}
				if len(out.Upstreams) == 0 {
					out.Upstreams = ups
				}
				if out.Source == "" {
					out.Source = "bgpview"
				}
			}
		}
	}

	if out.OriginASN == 0 && len(out.Upstreams) == 0 && len(out.History) == 0 {
		if lgErr != nil {
			return nil, lgErr
		}
		return nil, fmt.Errorf("no BGP data for %s", prefix)
	}

	// Fill human names from local PeeringDB bulk feed (no extra network calls)
	if out.OriginASN > 0 && out.OriginName == "" {
		out.OriginName = NameFromBulk(ctx, out.OriginASN)
	}
	for i := range out.Upstreams {
		if out.Upstreams[i].Name == "" {
			out.Upstreams[i].Name = NameFromBulk(ctx, out.Upstreams[i].ASN)
		}
	}
	for i := range out.History {
		if out.History[i].Name == "" {
			out.History[i].Name = NameFromBulk(ctx, out.History[i].ASN)
		}
	}
	cache.Put("prefix-bgp", prefix, *out, 6*time.Hour)
	return out, nil
}
